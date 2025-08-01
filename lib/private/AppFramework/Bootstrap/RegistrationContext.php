<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OC\AppFramework\Bootstrap;

use Closure;
use OC\Support\CrashReport\Registry;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\Middleware;
use OCP\AppFramework\Services\InitialStateProvider;
use OCP\Authentication\IAlternativeLogin;
use OCP\Calendar\ICalendarProvider;
use OCP\Calendar\Resource\IBackend as IResourceBackend;
use OCP\Calendar\Room\IBackend as IRoomBackend;
use OCP\Capabilities\ICapability;
use OCP\Collaboration\Reference\IReferenceProvider;
use OCP\Config\Lexicon\ILexicon;
use OCP\Dashboard\IManager;
use OCP\Dashboard\IWidget;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\Template\ICustomTemplateProvider;
use OCP\Http\WellKnown\IHandler;
use OCP\Mail\Provider\IProvider as IMailProvider;
use OCP\Notification\INotifier;
use OCP\Profile\ILinkAction;
use OCP\Search\IProvider;
use OCP\Settings\IDeclarativeSettingsForm;
use OCP\SetupCheck\ISetupCheck;
use OCP\Share\IPublicShareTemplateProvider;
use OCP\SpeechToText\ISpeechToTextProvider;
use OCP\Support\CrashReport\IReporter;
use OCP\Talk\ITalkBackend;
use OCP\Teams\ITeamResourceProvider;
use OCP\TextProcessing\IProvider as ITextProcessingProvider;
use OCP\Translation\ITranslationProvider;
use OCP\UserMigration\IMigrator as IUserMigrator;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;
use function array_shift;

class RegistrationContext {
	/** @var ServiceRegistration<ICapability>[] */
	private $capabilities = [];

	/** @var ServiceRegistration<IReporter>[] */
	private $crashReporters = [];

	/** @var ServiceRegistration<IWidget>[] */
	private $dashboardPanels = [];

	/** @var ServiceRegistration<ILinkAction>[] */
	private $profileLinkActions = [];

	/** @var null|ServiceRegistration<ITalkBackend> */
	private $talkBackendRegistration = null;

	/** @var ServiceRegistration<IResourceBackend>[] */
	private $calendarResourceBackendRegistrations = [];

	/** @var ServiceRegistration<IRoomBackend>[] */
	private $calendarRoomBackendRegistrations = [];

	/** @var ServiceRegistration<IUserMigrator>[] */
	private $userMigrators = [];

	/** @var ServiceFactoryRegistration[] */
	private $services = [];

	/** @var ServiceAliasRegistration[] */
	private $aliases = [];

	/** @var ParameterRegistration[] */
	private $parameters = [];

	/** @var EventListenerRegistration[] */
	private $eventListeners = [];

	/** @var MiddlewareRegistration[] */
	private $middlewares = [];

	/** @var ServiceRegistration<IProvider>[] */
	private $searchProviders = [];

	/** @var ServiceRegistration<IAlternativeLogin>[] */
	private $alternativeLogins = [];

	/** @var ServiceRegistration<InitialStateProvider>[] */
	private $initialStates = [];

	/** @var ServiceRegistration<IHandler>[] */
	private $wellKnownHandlers = [];

	/** @var ServiceRegistration<ISpeechToTextProvider>[] */
	private $speechToTextProviders = [];

	/** @var ServiceRegistration<ITextProcessingProvider>[] */
	private $textProcessingProviders = [];

	/** @var ServiceRegistration<ICustomTemplateProvider>[] */
	private $templateProviders = [];

	/** @var ServiceRegistration<ITranslationProvider>[] */
	private $translationProviders = [];

	/** @var ServiceRegistration<INotifier>[] */
	private $notifierServices = [];

	/** @var ServiceRegistration<\OCP\Authentication\TwoFactorAuth\IProvider>[] */
	private $twoFactorProviders = [];

	/** @var ServiceRegistration<ICalendarProvider>[] */
	private $calendarProviders = [];

	/** @var ServiceRegistration<IReferenceProvider>[] */
	private array $referenceProviders = [];

	/** @var ServiceRegistration<\OCP\TextToImage\IProvider>[] */
	private $textToImageProviders = [];

	/** @var ParameterRegistration[] */
	private $sensitiveMethods = [];

	/** @var ServiceRegistration<IPublicShareTemplateProvider>[] */
	private $publicShareTemplateProviders = [];

	private LoggerInterface $logger;

	/** @var ServiceRegistration<ISetupCheck>[] */
	private array $setupChecks = [];

	/** @var PreviewProviderRegistration[] */
	private array $previewProviders = [];

	/** @var ServiceRegistration<IDeclarativeSettingsForm>[] */
	private array $declarativeSettings = [];

	/** @var array<array-key, string> */
	private array $configLexiconClasses = [];

	/** @var ServiceRegistration<ITeamResourceProvider>[] */
	private array $teamResourceProviders = [];

	/** @var ServiceRegistration<\OCP\TaskProcessing\IProvider>[] */
	private array $taskProcessingProviders = [];

	/** @var ServiceRegistration<\OCP\TaskProcessing\ITaskType>[] */
	private array $taskProcessingTaskTypes = [];

	/** @var ServiceRegistration<\OCP\Files\Conversion\IConversionProvider>[] */
	private array $fileConversionProviders = [];

	/** @var ServiceRegistration<IMailProvider>[] */
	private $mailProviders = [];

	public function __construct(LoggerInterface $logger) {
		$this->logger = $logger;
	}

	public function for(string $appId): IRegistrationContext {
		return new class($appId, $this) implements IRegistrationContext {
			/** @var string */
			private $appId;

			/** @var RegistrationContext */
			private $context;

			public function __construct(string $appId, RegistrationContext $context) {
				$this->appId = $appId;
				$this->context = $context;
			}

			public function registerCapability(string $capability): void {
				$this->context->registerCapability(
					$this->appId,
					$capability
				);
			}

			public function registerCrashReporter(string $reporterClass): void {
				$this->context->registerCrashReporter(
					$this->appId,
					$reporterClass
				);
			}

			public function registerDashboardWidget(string $widgetClass): void {
				$this->context->registerDashboardPanel(
					$this->appId,
					$widgetClass
				);
			}

			public function registerService(string $name, callable $factory, bool $shared = true): void {
				$this->context->registerService(
					$this->appId,
					$name,
					$factory,
					$shared
				);
			}

			public function registerServiceAlias(string $alias, string $target): void {
				$this->context->registerServiceAlias(
					$this->appId,
					$alias,
					$target
				);
			}

			public function registerParameter(string $name, $value): void {
				$this->context->registerParameter(
					$this->appId,
					$name,
					$value
				);
			}

			public function registerEventListener(string $event, string $listener, int $priority = 0): void {
				$this->context->registerEventListener(
					$this->appId,
					$event,
					$listener,
					$priority
				);
			}

			public function registerMiddleware(string $class, bool $global = false): void {
				$this->context->registerMiddleware(
					$this->appId,
					$class,
					$global,
				);
			}

			public function registerSearchProvider(string $class): void {
				$this->context->registerSearchProvider(
					$this->appId,
					$class
				);
			}

			public function registerAlternativeLogin(string $class): void {
				$this->context->registerAlternativeLogin(
					$this->appId,
					$class
				);
			}

			public function registerInitialStateProvider(string $class): void {
				$this->context->registerInitialState(
					$this->appId,
					$class
				);
			}

			public function registerWellKnownHandler(string $class): void {
				$this->context->registerWellKnown(
					$this->appId,
					$class
				);
			}

			public function registerSpeechToTextProvider(string $providerClass): void {
				$this->context->registerSpeechToTextProvider(
					$this->appId,
					$providerClass
				);
			}
			public function registerTextProcessingProvider(string $providerClass): void {
				$this->context->registerTextProcessingProvider(
					$this->appId,
					$providerClass
				);
			}

			public function registerTextToImageProvider(string $providerClass): void {
				$this->context->registerTextToImageProvider(
					$this->appId,
					$providerClass
				);
			}

			public function registerTemplateProvider(string $providerClass): void {
				$this->context->registerTemplateProvider(
					$this->appId,
					$providerClass
				);
			}

			public function registerTranslationProvider(string $providerClass): void {
				$this->context->registerTranslationProvider(
					$this->appId,
					$providerClass
				);
			}

			public function registerNotifierService(string $notifierClass): void {
				$this->context->registerNotifierService(
					$this->appId,
					$notifierClass
				);
			}

			public function registerTwoFactorProvider(string $twoFactorProviderClass): void {
				$this->context->registerTwoFactorProvider(
					$this->appId,
					$twoFactorProviderClass
				);
			}

			public function registerPreviewProvider(string $previewProviderClass, string $mimeTypeRegex): void {
				$this->context->registerPreviewProvider(
					$this->appId,
					$previewProviderClass,
					$mimeTypeRegex
				);
			}

			public function registerCalendarProvider(string $class): void {
				$this->context->registerCalendarProvider(
					$this->appId,
					$class
				);
			}

			public function registerReferenceProvider(string $class): void {
				$this->context->registerReferenceProvider(
					$this->appId,
					$class
				);
			}

			public function registerProfileLinkAction(string $actionClass): void {
				$this->context->registerProfileLinkAction(
					$this->appId,
					$actionClass
				);
			}

			public function registerTalkBackend(string $backend): void {
				$this->context->registerTalkBackend(
					$this->appId,
					$backend
				);
			}

			public function registerCalendarResourceBackend(string $class): void {
				$this->context->registerCalendarResourceBackend(
					$this->appId,
					$class
				);
			}

			public function registerTeamResourceProvider(string $class) : void {
				$this->context->registerTeamResourceProvider(
					$this->appId,
					$class
				);
			}

			public function registerCalendarRoomBackend(string $class): void {
				$this->context->registerCalendarRoomBackend(
					$this->appId,
					$class
				);
			}

			public function registerUserMigrator(string $migratorClass): void {
				$this->context->registerUserMigrator(
					$this->appId,
					$migratorClass
				);
			}

			public function registerSensitiveMethods(string $class, array $methods): void {
				$this->context->registerSensitiveMethods(
					$this->appId,
					$class,
					$methods
				);
			}

			public function registerPublicShareTemplateProvider(string $class): void {
				$this->context->registerPublicShareTemplateProvider(
					$this->appId,
					$class
				);
			}

			public function registerSetupCheck(string $setupCheckClass): void {
				$this->context->registerSetupCheck(
					$this->appId,
					$setupCheckClass
				);
			}

			public function registerDeclarativeSettings(string $declarativeSettingsClass): void {
				$this->context->registerDeclarativeSettings(
					$this->appId,
					$declarativeSettingsClass
				);
			}

			public function registerTaskProcessingProvider(string $taskProcessingProviderClass): void {
				$this->context->registerTaskProcessingProvider(
					$this->appId,
					$taskProcessingProviderClass
				);
			}

			public function registerTaskProcessingTaskType(string $taskProcessingTaskTypeClass): void {
				$this->context->registerTaskProcessingTaskType(
					$this->appId,
					$taskProcessingTaskTypeClass
				);
			}

			public function registerFileConversionProvider(string $class): void {
				$this->context->registerFileConversionProvider(
					$this->appId,
					$class
				);
			}

			public function registerMailProvider(string $class): void {
				$this->context->registerMailProvider(
					$this->appId,
					$class
				);
			}

			public function registerConfigLexicon(string $configLexiconClass): void {
				$this->context->registerConfigLexicon(
					$this->appId,
					$configLexiconClass
				);
			}
		};
	}

	/**
	 * @psalm-param class-string<ICapability> $capability
	 */
	public function registerCapability(string $appId, string $capability): void {
		$this->capabilities[] = new ServiceRegistration($appId, $capability);
	}

	/**
	 * @psalm-param class-string<IReporter> $reporterClass
	 */
	public function registerCrashReporter(string $appId, string $reporterClass): void {
		$this->crashReporters[] = new ServiceRegistration($appId, $reporterClass);
	}

	/**
	 * @psalm-param class-string<IWidget> $panelClass
	 */
	public function registerDashboardPanel(string $appId, string $panelClass): void {
		$this->dashboardPanels[] = new ServiceRegistration($appId, $panelClass);
	}

	public function registerService(string $appId, string $name, callable $factory, bool $shared = true): void {
		$this->services[] = new ServiceFactoryRegistration($appId, $name, $factory, $shared);
	}

	public function registerServiceAlias(string $appId, string $alias, string $target): void {
		$this->aliases[] = new ServiceAliasRegistration($appId, $alias, $target);
	}

	public function registerParameter(string $appId, string $name, $value): void {
		$this->parameters[] = new ParameterRegistration($appId, $name, $value);
	}

	public function registerEventListener(string $appId, string $event, string $listener, int $priority = 0): void {
		$this->eventListeners[] = new EventListenerRegistration($appId, $event, $listener, $priority);
	}

	/**
	 * @psalm-param class-string<Middleware> $class
	 */
	public function registerMiddleware(string $appId, string $class, bool $global): void {
		$this->middlewares[] = new MiddlewareRegistration($appId, $class, $global);
	}

	public function registerSearchProvider(string $appId, string $class) {
		$this->searchProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerAlternativeLogin(string $appId, string $class): void {
		$this->alternativeLogins[] = new ServiceRegistration($appId, $class);
	}

	public function registerInitialState(string $appId, string $class): void {
		$this->initialStates[] = new ServiceRegistration($appId, $class);
	}

	public function registerWellKnown(string $appId, string $class): void {
		$this->wellKnownHandlers[] = new ServiceRegistration($appId, $class);
	}

	public function registerSpeechToTextProvider(string $appId, string $class): void {
		$this->speechToTextProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerTextProcessingProvider(string $appId, string $class): void {
		$this->textProcessingProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerTextToImageProvider(string $appId, string $class): void {
		$this->textToImageProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerTemplateProvider(string $appId, string $class): void {
		$this->templateProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerTranslationProvider(string $appId, string $class): void {
		$this->translationProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerNotifierService(string $appId, string $class): void {
		$this->notifierServices[] = new ServiceRegistration($appId, $class);
	}

	public function registerTwoFactorProvider(string $appId, string $class): void {
		$this->twoFactorProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerPreviewProvider(string $appId, string $class, string $mimeTypeRegex): void {
		$this->previewProviders[] = new PreviewProviderRegistration($appId, $class, $mimeTypeRegex);
	}

	public function registerCalendarProvider(string $appId, string $class): void {
		$this->calendarProviders[] = new ServiceRegistration($appId, $class);
	}

	public function registerReferenceProvider(string $appId, string $class): void {
		$this->referenceProviders[] = new ServiceRegistration($appId, $class);
	}

	/**
	 * @psalm-param class-string<ILinkAction> $actionClass
	 */
	public function registerProfileLinkAction(string $appId, string $actionClass): void {
		$this->profileLinkActions[] = new ServiceRegistration($appId, $actionClass);
	}

	/**
	 * @psalm-param class-string<ITalkBackend> $backend
	 */
	public function registerTalkBackend(string $appId, string $backend) {
		// Some safeguards for invalid registrations
		if ($appId !== 'spreed') {
			throw new RuntimeException('Only the Talk app is allowed to register a Talk backend');
		}
		if ($this->talkBackendRegistration !== null) {
			throw new RuntimeException('There can only be one Talk backend');
		}

		$this->talkBackendRegistration = new ServiceRegistration($appId, $backend);
	}

	public function registerCalendarResourceBackend(string $appId, string $class) {
		$this->calendarResourceBackendRegistrations[] = new ServiceRegistration(
			$appId,
			$class,
		);
	}

	public function registerCalendarRoomBackend(string $appId, string $class) {
		$this->calendarRoomBackendRegistrations[] = new ServiceRegistration(
			$appId,
			$class,
		);
	}

	/**
	 * @psalm-param class-string<ITeamResourceProvider> $class
	 */
	public function registerTeamResourceProvider(string $appId, string $class) {
		$this->teamResourceProviders[] = new ServiceRegistration(
			$appId,
			$class
		);
	}

	/**
	 * @psalm-param class-string<IUserMigrator> $migratorClass
	 */
	public function registerUserMigrator(string $appId, string $migratorClass): void {
		$this->userMigrators[] = new ServiceRegistration($appId, $migratorClass);
	}

	public function registerSensitiveMethods(string $appId, string $class, array $methods): void {
		$methods = array_filter($methods, 'is_string');
		$this->sensitiveMethods[] = new ParameterRegistration($appId, $class, $methods);
	}

	public function registerPublicShareTemplateProvider(string $appId, string $class): void {
		$this->publicShareTemplateProviders[] = new ServiceRegistration($appId, $class);
	}

	/**
	 * @psalm-param class-string<ISetupCheck> $setupCheckClass
	 */
	public function registerSetupCheck(string $appId, string $setupCheckClass): void {
		$this->setupChecks[] = new ServiceRegistration($appId, $setupCheckClass);
	}

	/**
	 * @psalm-param class-string<IDeclarativeSettingsForm> $declarativeSettingsClass
	 */
	public function registerDeclarativeSettings(string $appId, string $declarativeSettingsClass): void {
		$this->declarativeSettings[] = new ServiceRegistration($appId, $declarativeSettingsClass);
	}

	/**
	 * @psalm-param class-string<\OCP\TaskProcessing\IProvider> $declarativeSettingsClass
	 */
	public function registerTaskProcessingProvider(string $appId, string $taskProcessingProviderClass): void {
		$this->taskProcessingProviders[] = new ServiceRegistration($appId, $taskProcessingProviderClass);
	}

	/**
	 * @psalm-param class-string<\OCP\TaskProcessing\ITaskType> $declarativeSettingsClass
	 */
	public function registerTaskProcessingTaskType(string $appId, string $taskProcessingTaskTypeClass) {
		$this->taskProcessingTaskTypes[] = new ServiceRegistration($appId, $taskProcessingTaskTypeClass);
	}

	/**
	 * @psalm-param class-string<\OCP\Files\Conversion\IConversionProvider> $class
	 */
	public function registerFileConversionProvider(string $appId, string $class): void {
		$this->fileConversionProviders[] = new ServiceRegistration($appId, $class);
	}

	/**
	 * @psalm-param class-string<IMailProvider> $migratorClass
	 */
	public function registerMailProvider(string $appId, string $class): void {
		$this->mailProviders[] = new ServiceRegistration($appId, $class);
	}

	/**
	 * @psalm-param class-string<ILexicon> $configLexiconClass
	 */
	public function registerConfigLexicon(string $appId, string $configLexiconClass): void {
		$this->configLexiconClasses[$appId] = $configLexiconClass;
	}

	/**
	 * @param App[] $apps
	 */
	public function delegateCapabilityRegistrations(array $apps): void {
		while (($registration = array_shift($this->capabilities)) !== null) {
			$appId = $registration->getAppId();
			if (!isset($apps[$appId])) {
				// If we land here something really isn't right. But at least we caught the
				// notice that is otherwise emitted for the undefined index
				$this->logger->error("App $appId not loaded for the capability registration");

				continue;
			}

			try {
				$apps[$appId]
					->getContainer()
					->registerCapability($registration->getService());
			} catch (Throwable $e) {
				$this->logger->error("Error during capability registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}
	}

	/**
	 * @param App[] $apps
	 */
	public function delegateCrashReporterRegistrations(array $apps, Registry $registry): void {
		while (($registration = array_shift($this->crashReporters)) !== null) {
			try {
				$registry->registerLazy($registration->getService());
			} catch (Throwable $e) {
				$appId = $registration->getAppId();
				$this->logger->error("Error during crash reporter registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}
	}

	public function delegateDashboardPanelRegistrations(IManager $dashboardManager): void {
		while (($panel = array_shift($this->dashboardPanels)) !== null) {
			try {
				$dashboardManager->lazyRegisterWidget($panel->getService(), $panel->getAppId());
			} catch (Throwable $e) {
				$appId = $panel->getAppId();
				$this->logger->error("Error during dashboard registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}
	}

	public function delegateEventListenerRegistrations(IEventDispatcher $eventDispatcher): void {
		while (($registration = array_shift($this->eventListeners)) !== null) {
			try {
				$eventDispatcher->addServiceListener(
					$registration->getEvent(),
					$registration->getService(),
					$registration->getPriority()
				);
			} catch (Throwable $e) {
				$appId = $registration->getAppId();
				$this->logger->error("Error during event listener registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}
	}

	/**
	 * @param App[] $apps
	 */
	public function delegateContainerRegistrations(array $apps): void {
		while (($registration = array_shift($this->services)) !== null) {
			$appId = $registration->getAppId();
			if (!isset($apps[$appId])) {
				// If we land here something really isn't right. But at least we caught the
				// notice that is otherwise emitted for the undefined index
				$this->logger->error("App $appId not loaded for the container service registration");

				continue;
			}

			try {
				/**
				 * Register the service and convert the callable into a \Closure if necessary
				 */
				$apps[$appId]
					->getContainer()
					->registerService(
						$registration->getName(),
						Closure::fromCallable($registration->getFactory()),
						$registration->isShared()
					);
			} catch (Throwable $e) {
				$this->logger->error("Error during service registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}

		while (($registration = array_shift($this->aliases)) !== null) {
			$appId = $registration->getAppId();
			if (!isset($apps[$appId])) {
				// If we land here something really isn't right. But at least we caught the
				// notice that is otherwise emitted for the undefined index
				$this->logger->error("App $appId not loaded for the container alias registration");

				continue;
			}

			try {
				$apps[$appId]
					->getContainer()
					->registerAlias(
						$registration->getAlias(),
						$registration->getTarget()
					);
			} catch (Throwable $e) {
				$this->logger->error("Error during service alias registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}

		while (($registration = array_shift($this->parameters)) !== null) {
			$appId = $registration->getAppId();
			if (!isset($apps[$appId])) {
				// If we land here something really isn't right. But at least we caught the
				// notice that is otherwise emitted for the undefined index
				$this->logger->error("App $appId not loaded for the container parameter registration");

				continue;
			}

			try {
				$apps[$appId]
					->getContainer()
					->registerParameter(
						$registration->getName(),
						$registration->getValue()
					);
			} catch (Throwable $e) {
				$this->logger->error("Error during service parameter registration of $appId: " . $e->getMessage(), [
					'exception' => $e,
				]);
			}
		}
	}

	/**
	 * @return MiddlewareRegistration[]
	 */
	public function getMiddlewareRegistrations(): array {
		return $this->middlewares;
	}

	/**
	 * @return ServiceRegistration<IProvider>[]
	 */
	public function getSearchProviders(): array {
		return $this->searchProviders;
	}

	/**
	 * @return ServiceRegistration<IAlternativeLogin>[]
	 */
	public function getAlternativeLogins(): array {
		return $this->alternativeLogins;
	}

	/**
	 * @return ServiceRegistration<InitialStateProvider>[]
	 */
	public function getInitialStates(): array {
		return $this->initialStates;
	}

	/**
	 * @return ServiceRegistration<IHandler>[]
	 */
	public function getWellKnownHandlers(): array {
		return $this->wellKnownHandlers;
	}

	/**
	 * @return ServiceRegistration<ISpeechToTextProvider>[]
	 */
	public function getSpeechToTextProviders(): array {
		return $this->speechToTextProviders;
	}

	/**
	 * @return ServiceRegistration<ITextProcessingProvider>[]
	 */
	public function getTextProcessingProviders(): array {
		return $this->textProcessingProviders;
	}

	/**
	 * @return ServiceRegistration<\OCP\TextToImage\IProvider>[]
	 */
	public function getTextToImageProviders(): array {
		return $this->textToImageProviders;
	}

	/**
	 * @return ServiceRegistration<ICustomTemplateProvider>[]
	 */
	public function getTemplateProviders(): array {
		return $this->templateProviders;
	}

	/**
	 * @return ServiceRegistration<ITranslationProvider>[]
	 */
	public function getTranslationProviders(): array {
		return $this->translationProviders;
	}

	/**
	 * @return ServiceRegistration<INotifier>[]
	 */
	public function getNotifierServices(): array {
		return $this->notifierServices;
	}

	/**
	 * @return ServiceRegistration<\OCP\Authentication\TwoFactorAuth\IProvider>[]
	 */
	public function getTwoFactorProviders(): array {
		return $this->twoFactorProviders;
	}

	/**
	 * @return PreviewProviderRegistration[]
	 */
	public function getPreviewProviders(): array {
		return $this->previewProviders;
	}

	/**
	 * @return ServiceRegistration<ICalendarProvider>[]
	 */
	public function getCalendarProviders(): array {
		return $this->calendarProviders;
	}

	/**
	 * @return ServiceRegistration<IReferenceProvider>[]
	 */
	public function getReferenceProviders(): array {
		return $this->referenceProviders;
	}

	/**
	 * @return ServiceRegistration<ILinkAction>[]
	 */
	public function getProfileLinkActions(): array {
		return $this->profileLinkActions;
	}

	/**
	 * @return ServiceRegistration|null
	 * @psalm-return ServiceRegistration<ITalkBackend>|null
	 */
	public function getTalkBackendRegistration(): ?ServiceRegistration {
		return $this->talkBackendRegistration;
	}

	/**
	 * @return ServiceRegistration[]
	 * @psalm-return ServiceRegistration<IResourceBackend>[]
	 */
	public function getCalendarResourceBackendRegistrations(): array {
		return $this->calendarResourceBackendRegistrations;
	}

	/**
	 * @return ServiceRegistration[]
	 * @psalm-return ServiceRegistration<IRoomBackend>[]
	 */
	public function getCalendarRoomBackendRegistrations(): array {
		return $this->calendarRoomBackendRegistrations;
	}

	/**
	 * @return ServiceRegistration<IUserMigrator>[]
	 */
	public function getUserMigrators(): array {
		return $this->userMigrators;
	}

	/**
	 * @return ParameterRegistration[]
	 */
	public function getSensitiveMethods(): array {
		return $this->sensitiveMethods;
	}

	/**
	 * @return ServiceRegistration<IPublicShareTemplateProvider>[]
	 */
	public function getPublicShareTemplateProviders(): array {
		return $this->publicShareTemplateProviders;
	}

	/**
	 * @return ServiceRegistration<ISetupCheck>[]
	 */
	public function getSetupChecks(): array {
		return $this->setupChecks;
	}

	/**
	 * @return ServiceRegistration<ITeamResourceProvider>[]
	 */
	public function getTeamResourceProviders(): array {
		return $this->teamResourceProviders;
	}

	/**
	 * @return ServiceRegistration<IDeclarativeSettingsForm>[]
	 */
	public function getDeclarativeSettings(): array {
		return $this->declarativeSettings;
	}

	/**
	 * @return ServiceRegistration<\OCP\TaskProcessing\IProvider>[]
	 */
	public function getTaskProcessingProviders(): array {
		return $this->taskProcessingProviders;
	}

	/**
	 * @return ServiceRegistration<\OCP\TaskProcessing\ITaskType>[]
	 */
	public function getTaskProcessingTaskTypes(): array {
		return $this->taskProcessingTaskTypes;
	}

	/**
	 * @return ServiceRegistration<\OCP\Files\Conversion\IConversionProvider>[]
	 */
	public function getFileConversionProviders(): array {
		return $this->fileConversionProviders;
	}

	/**
	 * @return ServiceRegistration<IMailProvider>[]
	 */
	public function getMailProviders(): array {
		return $this->mailProviders;
	}

	/**
	 * returns IConfigLexicon registered by the app.
	 * null if none registered.
	 *
	 * @param string $appId
	 *
	 * @return ILexicon|null
	 */
	public function getConfigLexicon(string $appId): ?ILexicon {
		if (!array_key_exists($appId, $this->configLexiconClasses)) {
			return null;
		}

		return \OCP\Server::get($this->configLexiconClasses[$appId]);
	}
}
