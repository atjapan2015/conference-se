/*
 * Copyright (c) 2018, 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.examples.conference.se;

import static io.helidon.config.PollingStrategies.regular;
import static java.time.Duration.ofSeconds;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.logging.LogManager;

import org.eclipse.microprofile.health.HealthCheckResponse;

import io.helidon.common.CollectionsHelper;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.config.PollingStrategies;
import io.helidon.health.HealthSupport;
import io.helidon.health.checks.HealthChecks;
import io.helidon.media.jsonp.server.JsonSupport;
import io.helidon.metrics.MetricsSupport;
import io.helidon.security.CompositeProviderFlag;
import io.helidon.security.CompositeProviderSelectionPolicy;
import io.helidon.security.Security;
import io.helidon.security.integration.webserver.WebSecurity;
import io.helidon.security.providers.httpauth.HttpBasicAuthProvider;
import io.helidon.security.providers.httpauth.UserStore;
import io.helidon.security.providers.httpsign.HttpSignProvider;
import io.helidon.security.providers.httpsign.InboundClientDefinition;
import io.helidon.security.providers.httpsign.SignedHeadersConfig;
import io.helidon.security.spi.ProviderSelectionPolicy;
import io.helidon.security.spi.SecurityProvider;
import io.helidon.tracing.TracerBuilder;
import io.helidon.webserver.Routing;
import io.helidon.webserver.ServerConfiguration;
import io.helidon.webserver.WebServer;

/**
 * Simple Hello World rest application.
 */
public final class Main {

	private static final Map<String, UserStore.User> USERS = new HashMap<>();

	static {
		USERS.put("jack", new HelidonUser("jack", "jackIsGreat", "admin"));
		USERS.put("jill", new HelidonUser("jill", "jillToo", "user"));
	}

	/**
	 * Cannot be instantiated.
	 */
	private Main() {
	}

	/**
	 * Application main entry point.
	 * 
	 * @param args command line arguments.
	 * @throws IOException if there are problems reading logging properties
	 */
	public static void main(final String[] args) throws IOException {
		startServer();
	}

	/**
	 * Start the server.
	 * 
	 * @return the created {@link WebServer} instance
	 * @throws IOException if there are problems reading logging properties
	 */
	static WebServer startServer() throws IOException {

		// load logging configuration
		LogManager.getLogManager().readConfiguration(Main.class.getResourceAsStream("/logging.properties"));

		// By default this will pick up application.yaml from the classpath
		// Config config = Config.create();
		Config config = buildConfig();

		// Get webserver config from the "server" section of application.yaml
		// ServerConfiguration serverConfig =
		// ServerConfiguration.create(config.get("server"));
		ServerConfiguration serverConfig = ServerConfiguration.builder(config.get("server"))
				.tracer(TracerBuilder.create("helidon-se").buildAndRegister()).build();

		WebServer server = WebServer.create(serverConfig, createRouting(config));

		// Try to start the server. If successful, print some info and arrange to
		// print a message at shutdown. If unsuccessful, print the exception.
		server.start().thenAccept(ws -> {
			System.out.println("WEB server is up! http://localhost:" + ws.port() + "/greet");
			ws.whenShutdown().thenRun(() -> System.out.println("WEB server is DOWN. Good bye!"));
		}).exceptionally(t -> {
			System.err.println("Startup failed: " + t.getMessage());
			t.printStackTrace(System.err);
			return null;
		});
//		server.start().thenAccept(Main::onStartup).exceptionally(Main::onStartupFailed);

		// Server threads are not daemon. No need to block. Just react.

		return server;
	}

//	private static Void onStartupFailed(Throwable t) {
//		System.out.println("Startup failed: " + t.getMessage());
//		t.printStackTrace();
//		return null;
//	}
//
//	private static void onStartup(WebServer ws) {
//		System.out.println("WEB server is up! http://localhost:" + ws.port() + "/greet");
//		ws.whenShutdown().thenAccept(Main::onShutdown);
//	}

//	private static void onShutdown(WebServer ws) {
//		System.out.println("WEB server is DOWN. Good bye!");
//	}

	/**
	 * Creates new {@link Routing}.
	 *
	 * @return routing configured with JSON support, a health check, and a service
	 * @param config configuration of this server
	 */
	private static Routing createRouting(Config config) {

		MetricsSupport metrics = MetricsSupport.create();
		GreetService greetService = new GreetService(config);
//		HealthSupport health = HealthSupport.builder().add(HealthChecks.healthChecks()) // Adds a convenient set of
//																						// checks
//				.build();
		HealthSupport health = HealthSupport.builder().config(config.get("health")) // support for exclusions and
																					// modification of context root
				.add(HealthChecks.healthChecks()) // built-in health checks
				.add(() -> HealthCheckResponse.named("custom") // a custom health check
						.up().withData("timestamp", System.currentTimeMillis()).build())
				.build();

		Security security = Security.create(config.get("security"));

//		Security security = Security.builder().providerSelectionPolicy(selectionPolicy())
//				.addProvider(AbacProvider.create()).addProvider(basicAuthentication(), "http-basic-auth")
//				.addProvider(httpSignatures(), "http-signatures").build();

		return Routing.builder().register(JsonSupport.create()).register(health) // Health at "/health"
				.register(metrics) // Metrics at "/metrics"
				.register(WebSecurity.create(security))
				.any("/greet/greeting[/{*}]", WebSecurity.authenticate().rolesAllowed("admin"))
				.any("/greet/jack", WebSecurity.authenticate()).register("/greet", greetService).build();
	}

	private static Function<ProviderSelectionPolicy.Providers, ProviderSelectionPolicy> selectionPolicy() {
		return CompositeProviderSelectionPolicy.builder()
				.addAuthenticationProvider("http-signatures", CompositeProviderFlag.OPTIONAL)
				.addAuthenticationProvider("http-basic-auth").build();
	}

	private static SecurityProvider basicAuthentication() {
		return HttpBasicAuthProvider.builder().userStore(Main::getUser).build();
	}

	private static SecurityProvider httpSignatures() {
		return HttpSignProvider.builder().optional(true)
				.inboundRequiredHeaders(SignedHeadersConfig.builder()
						.config("get",
								SignedHeadersConfig.HeadersConfig
										.create(CollectionsHelper.listOf("date", "(request-target)", "host")))
						.build())
				.addInbound(InboundClientDefinition.builder("helidon-mp").principalName("MP Service")
						.hmacSecret("badIdeaClearTextPassword!").build())
				.build();
	}

	private static Optional<UserStore.User> getUser(String login) {
		return Optional.ofNullable(USERS.get(login));
	}

	private static Config buildConfig() {

		return Config.builder().sources(
				// expected on development machine to override props for dev
				ConfigSources.file("conf/dev-conference-se.yaml").pollingStrategy(PollingStrategies::watch).optional(),
				// expected in k8s runtime to configure testing/production values
				ConfigSources.file("conf/conference-se.yaml").pollingStrategy(regular(ofSeconds(60))).optional(),
				ConfigSources.classpath("application.yaml").optional()).build();
	}

	// simplistic user implementation for the purpose of presentation
	private static final class HelidonUser implements UserStore.User {
		private final String login;
		private final String password;
		private final String role;

		private HelidonUser(String login, String password, String role) {
			this.login = login;
			this.password = password;
			this.role = role;
		}

		@Override
		public Collection<String> roles() {
			return CollectionsHelper.setOf(role);
		}

		@Override
		public String login() {
			return login;
		}

		@Override
		public char[] password() {
			return password.toCharArray();
		}
	}
}
