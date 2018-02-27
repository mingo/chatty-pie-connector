/*
 * Copyright 2017 AppDirect, Inc. and/or its affiliates
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.chattypie;

import ch.qos.logback.access.tomcat.LogbackValve;
import com.appdirect.sdk.ConnectorSdkConfiguration;
import com.appdirect.sdk.appmarket.DeveloperSpecificAppmarketCredentialsSupplier;
import com.appdirect.sdk.credentials.StringBackedCredentialsSupplier;
import com.appdirect.sdk.notification.HtmlEmailNotificationService;
import com.appdirect.sdk.security.openid.configuration.OpenIdSsoConfiguration;
import com.chattypie.config.SecurityConfiguration;
import com.chattypie.domain.ownership.verification.DomainOwnershipVerificationConfiguration;
import com.chattypie.handler.EventHandlersConfiguration;
import com.chattypie.service.appmarket.CompanyAccountServiceConfiguration;
import com.chattypie.service.chattypie.chatroom.ChatroomService;
import com.chattypie.service.chattypie.greeting.EmailContentGenerator;
import com.chattypie.service.chattypie.greeting.EmailNotificationService;
import com.chattypie.service.chattypie.greeting.NotificationService;
import com.chattypie.web.ReportGenerationController;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
@Import({
		ConnectorSdkConfiguration.class,
		OpenIdSsoConfiguration.class,
		EventHandlersConfiguration.class,
		ValidationEndpointConfiguration.class,
		CompanyAccountServiceConfiguration.class,
		LocalizationConfiguration.class,
		DomainOwnershipVerificationConfiguration.class,
		SecurityConfiguration.class
})
@EnableAutoConfiguration
public class RootConfiguration {

	@Bean
	public DeveloperSpecificAppmarketCredentialsSupplier environmentCredentialsSupplier(@Value("${connector.allowed.credentials}") String allowedCredentials) {
		return new StringBackedCredentialsSupplier(allowedCredentials);
	}

	@Bean
	public EmbeddedServletContainerFactory servletContainer() {
		// taken from http://stackoverflow.com/a/36790613/26605
		TomcatEmbeddedServletContainerFactory tomcat = new TomcatEmbeddedServletContainerFactory();
		LogbackValve logbackValve = new LogbackValve();
		logbackValve.setQuiet(true);
		logbackValve.setFilename("logback-access.xml");
		logbackValve.setAsyncSupported(true);
		tomcat.addContextValves(logbackValve);
		return tomcat;
	}

	@Bean
	@SuppressWarnings("SpringJavaAutowiringInspection")
	public HtmlEmailNotificationService emailNotificationService(JavaMailSender javaMailSender) {
		return new HtmlEmailNotificationService("do-not-reply@appdirect.com", javaMailSender);
	}

	@Bean
	public ExecutorService executorService() {
		return Executors.newFixedThreadPool(1);
	}

	@Bean
	public NotificationService newCompanyGreetingService(EmailContentGenerator contentGenerator,
														 HtmlEmailNotificationService emailNotificationService) {
		return new EmailNotificationService(
				contentGenerator,
				emailNotificationService
		);
	}

	@Bean
	public EmailContentGenerator emailContentGenerator() {
		return new EmailContentGenerator();
	}

	@Bean
	public ReportGenerationController reportGenerationController(
			ChatroomService chatroomService,
			NotificationService notificationService,
			@Value("${chatroom.report.subscriber}") String chatroomReportSubscriberEmail) {

		return new ReportGenerationController(
				chatroomService,
				notificationService,
				chatroomReportSubscriberEmail
		);
	}

	@Bean
	public LocalizedMessageService messageService(@Qualifier("localizedMessageSource") MessageSource messageSource) {
		return new LocalizedMessageServiceImpl(messageSource);
	}
}
