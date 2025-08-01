<?php

/**
 * SPDX-FileCopyrightText: 2016-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
namespace OCA\DAV\Connector\Sabre;

use OC\Files\View;
use OC\KnownUser\KnownUserService;
use OCA\DAV\AppInfo\PluginManager;
use OCA\DAV\CalDAV\DefaultCalendarValidator;
use OCA\DAV\CalDAV\Proxy\ProxyMapper;
use OCA\DAV\DAV\CustomPropertiesBackend;
use OCA\DAV\DAV\ViewOnlyPlugin;
use OCA\DAV\Files\BrowserErrorPagePlugin;
use OCA\DAV\Files\Sharing\RootCollection;
use OCA\DAV\Upload\CleanupService;
use OCA\Theming\ThemingDefaults;
use OCP\Accounts\IAccountManager;
use OCP\App\IAppManager;
use OCP\Comments\ICommentsManager;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\Folder;
use OCP\Files\IFilenameValidator;
use OCP\Files\IRootFolder;
use OCP\Files\Mount\IMountManager;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IPreview;
use OCP\IRequest;
use OCP\ITagManager;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\SabrePluginEvent;
use OCP\SystemTag\ISystemTagManager;
use OCP\SystemTag\ISystemTagObjectMapper;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Auth\Plugin;
use Sabre\DAV\SimpleCollection;

class ServerFactory {

	public function __construct(
		private IConfig $config,
		private LoggerInterface $logger,
		private IDBConnection $databaseConnection,
		private IUserSession $userSession,
		private IMountManager $mountManager,
		private ITagManager $tagManager,
		private IRequest $request,
		private IPreview $previewManager,
		private IEventDispatcher $eventDispatcher,
		private IL10N $l10n,
	) {
	}

	/**
	 * @param callable $viewCallBack callback that should return the view for the dav endpoint
	 */
	public function createServer(
		bool $isPublicShare,
		string $baseUri,
		string $requestUri,
		Plugin $authPlugin,
		callable $viewCallBack,
	): Server {
		// Fire up server
		if ($isPublicShare) {
			$rootCollection = new SimpleCollection('root');
			$tree = new CachingTree($rootCollection);
		} else {
			$rootCollection = null;
			$tree = new ObjectTree();
		}
		$server = new Server($tree);
		// Set URL explicitly due to reverse-proxy situations
		$server->httpRequest->setUrl($requestUri);
		$server->setBaseUri($baseUri);

		// Load plugins
		$server->addPlugin(new MaintenancePlugin($this->config, $this->l10n));
		$server->addPlugin(new BlockLegacyClientPlugin(
			$this->config,
			\OCP\Server::get(ThemingDefaults::class),
		));
		$server->addPlugin(new AnonymousOptionsPlugin());
		$server->addPlugin($authPlugin);
		// FIXME: The following line is a workaround for legacy components relying on being able to send a GET to /
		$server->addPlugin(new DummyGetResponsePlugin());
		$server->addPlugin(new ExceptionLoggerPlugin('webdav', $this->logger));
		$server->addPlugin(new LockPlugin());

		$server->addPlugin(new RequestIdHeaderPlugin($this->request));

		$server->addPlugin(new ZipFolderPlugin(
			$tree,
			$this->logger,
			$this->eventDispatcher,
		));

		// Some WebDAV clients do require Class 2 WebDAV support (locking), since
		// we do not provide locking we emulate it using a fake locking plugin.
		if ($this->request->isUserAgent([
			'/WebDAVFS/',
			'/OneNote/',
			'/Microsoft-WebDAV-MiniRedir/',
		])) {
			$server->addPlugin(new FakeLockerPlugin());
		}

		if (BrowserErrorPagePlugin::isBrowserRequest($this->request)) {
			$server->addPlugin(new BrowserErrorPagePlugin());
		}

		// wait with registering these until auth is handled and the filesystem is setup
		$server->on('beforeMethod:*', function () use ($server, $tree, $viewCallBack, $isPublicShare, $rootCollection): void {
			// ensure the skeleton is copied
			$userFolder = \OC::$server->getUserFolder();

			/** @var View $view */
			$view = $viewCallBack($server);
			if ($userFolder instanceof Folder && $userFolder->getPath() === $view->getRoot()) {
				$rootInfo = $userFolder;
			} else {
				$rootInfo = $view->getFileInfo('');
			}

			// Create Nextcloud Dir
			if ($rootInfo->getType() === 'dir') {
				$root = new Directory($view, $rootInfo, $tree);
			} else {
				$root = new File($view, $rootInfo);
			}

			if ($isPublicShare) {
				$userPrincipalBackend = new Principal(
					\OCP\Server::get(IUserManager::class),
					\OCP\Server::get(IGroupManager::class),
					\OCP\Server::get(IAccountManager::class),
					\OCP\Server::get(\OCP\Share\IManager::class),
					\OCP\Server::get(IUserSession::class),
					\OCP\Server::get(IAppManager::class),
					\OCP\Server::get(ProxyMapper::class),
					\OCP\Server::get(KnownUserService::class),
					\OCP\Server::get(IConfig::class),
					\OC::$server->getL10NFactory(),
				);

				// Mount the share collection at /public.php/dav/shares/<share token>
				$rootCollection->addChild(new RootCollection(
					$root,
					$userPrincipalBackend,
					'principals/shares',
				));

				// Mount the upload collection at /public.php/dav/uploads/<share token>
				$rootCollection->addChild(new \OCA\DAV\Upload\RootCollection(
					$userPrincipalBackend,
					'principals/shares',
					\OCP\Server::get(CleanupService::class),
					\OCP\Server::get(IRootFolder::class),
					\OCP\Server::get(IUserSession::class),
					\OCP\Server::get(\OCP\Share\IManager::class),
				));
			} else {
				/** @var ObjectTree $tree */
				$tree->init($root, $view, $this->mountManager);
			}

			$server->addPlugin(
				new FilesPlugin(
					$tree,
					$this->config,
					$this->request,
					$this->previewManager,
					$this->userSession,
					\OCP\Server::get(IFilenameValidator::class),
					\OCP\Server::get(IAccountManager::class),
					false,
					!$this->config->getSystemValue('debug', false)
				)
			);
			$server->addPlugin(new QuotaPlugin($view));
			$server->addPlugin(new ChecksumUpdatePlugin());

			// Allow view-only plugin for webdav requests
			$server->addPlugin(new ViewOnlyPlugin(
				$userFolder,
			));

			if ($this->userSession->isLoggedIn()) {
				$server->addPlugin(new TagsPlugin($tree, $this->tagManager, $this->eventDispatcher, $this->userSession));
				$server->addPlugin(new SharesPlugin(
					$tree,
					$this->userSession,
					$userFolder,
					\OCP\Server::get(\OCP\Share\IManager::class)
				));
				$server->addPlugin(new CommentPropertiesPlugin(\OCP\Server::get(ICommentsManager::class), $this->userSession));
				$server->addPlugin(new FilesReportPlugin(
					$tree,
					$view,
					\OCP\Server::get(ISystemTagManager::class),
					\OCP\Server::get(ISystemTagObjectMapper::class),
					\OCP\Server::get(ITagManager::class),
					$this->userSession,
					\OCP\Server::get(IGroupManager::class),
					$userFolder,
					\OCP\Server::get(IAppManager::class)
				));
				// custom properties plugin must be the last one
				$server->addPlugin(
					new \Sabre\DAV\PropertyStorage\Plugin(
						new CustomPropertiesBackend(
							$server,
							$tree,
							$this->databaseConnection,
							$this->userSession->getUser(),
							\OCP\Server::get(DefaultCalendarValidator::class),
						)
					)
				);
			}
			$server->addPlugin(new CopyEtagHeaderPlugin());

			// Load dav plugins from apps
			$event = new SabrePluginEvent($server);
			$this->eventDispatcher->dispatchTyped($event);
			$pluginManager = new PluginManager(
				\OC::$server,
				\OCP\Server::get(IAppManager::class)
			);
			foreach ($pluginManager->getAppPlugins() as $appPlugin) {
				$server->addPlugin($appPlugin);
			}
		}, 30); // priority 30: after auth (10) and acl(20), before lock(50) and handling the request
		return $server;
	}
}
