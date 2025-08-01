<?php

/**
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
namespace OCA\DAV\Connector\Sabre;

use OC\KnownUser\KnownUserService;
use OCA\Circles\Api\v1\Circles;
use OCA\Circles\Exceptions\CircleNotFoundException;
use OCA\Circles\Model\Circle;
use OCA\DAV\CalDAV\Proxy\ProxyMapper;
use OCA\DAV\Traits\PrincipalProxyTrait;
use OCP\Accounts\IAccountManager;
use OCP\Accounts\IAccountProperty;
use OCP\Accounts\PropertyDoesNotExistException;
use OCP\App\IAppManager;
use OCP\AppFramework\QueryException;
use OCP\Constants;
use OCP\IConfig;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Share\IManager as IShareManager;
use Sabre\DAV\Exception;
use Sabre\DAV\PropPatch;
use Sabre\DAVACL\PrincipalBackend\BackendInterface;

class Principal implements BackendInterface {

	/** @var string */
	private $principalPrefix;

	/** @var bool */
	private $hasGroups;

	/** @var bool */
	private $hasCircles;

	/** @var KnownUserService */
	private $knownUserService;

	public function __construct(
		private IUserManager $userManager,
		private IGroupManager $groupManager,
		private IAccountManager $accountManager,
		private IShareManager $shareManager,
		private IUserSession $userSession,
		private IAppManager $appManager,
		private ProxyMapper $proxyMapper,
		KnownUserService $knownUserService,
		private IConfig $config,
		private IFactory $languageFactory,
		string $principalPrefix = 'principals/users/',
	) {
		$this->principalPrefix = trim($principalPrefix, '/');
		$this->hasGroups = $this->hasCircles = ($principalPrefix === 'principals/users/');
		$this->knownUserService = $knownUserService;
	}

	use PrincipalProxyTrait {
		getGroupMembership as protected traitGetGroupMembership;
	}

	/**
	 * Returns a list of principals based on a prefix.
	 *
	 * This prefix will often contain something like 'principals'. You are only
	 * expected to return principals that are in this base path.
	 *
	 * You are expected to return at least a 'uri' for every user, you can
	 * return any additional properties if you wish so. Common properties are:
	 *   {DAV:}displayname
	 *
	 * @param string $prefixPath
	 * @return string[]
	 */
	public function getPrincipalsByPrefix($prefixPath) {
		$principals = [];

		if ($prefixPath === $this->principalPrefix) {
			foreach ($this->userManager->search('') as $user) {
				$principals[] = $this->userToPrincipal($user);
			}
		}

		return $principals;
	}

	/**
	 * Returns a specific principal, specified by it's path.
	 * The returned structure should be the exact same as from
	 * getPrincipalsByPrefix.
	 *
	 * @param string $path
	 * @return array
	 */
	public function getPrincipalByPath($path) {
		[$prefix, $name] = \Sabre\Uri\split($path);
		$decodedName = urldecode($name);

		if ($name === 'calendar-proxy-write' || $name === 'calendar-proxy-read') {
			[$prefix2, $name2] = \Sabre\Uri\split($prefix);

			if ($prefix2 === $this->principalPrefix) {
				$user = $this->userManager->get($name2);

				if ($user !== null) {
					return [
						'uri' => 'principals/users/' . $user->getUID() . '/' . $name,
					];
				}
				return null;
			}
		}

		if ($prefix === $this->principalPrefix) {
			// Depending on where it is called, it may happen that this function
			// is called either with a urlencoded version of the name or with a non-urlencoded one.
			// The urldecode function replaces %## and +, both of which are forbidden in usernames.
			// Hence there can be no ambiguity here and it is safe to call urldecode on all usernames
			$user = $this->userManager->get($decodedName);

			if ($user !== null) {
				return $this->userToPrincipal($user);
			}
		} elseif ($prefix === 'principals/circles') {
			if ($this->userSession->getUser() !== null) {
				// At the time of writing - 2021-01-19 — a mixed state is possible.
				// The second condition can be removed when this is fixed.
				return $this->circleToPrincipal($decodedName)
					?: $this->circleToPrincipal($name);
			}
		} elseif ($prefix === 'principals/groups') {
			// At the time of writing - 2021-01-19 — a mixed state is possible.
			// The second condition can be removed when this is fixed.
			$group = $this->groupManager->get($decodedName)
				?: $this->groupManager->get($name);
			if ($group instanceof IGroup) {
				return [
					'uri' => 'principals/groups/' . $name,
					'{DAV:}displayname' => $group->getDisplayName(),
				];
			}
		} elseif ($prefix === 'principals/system') {
			return [
				'uri' => 'principals/system/' . $name,
				'{DAV:}displayname' => $this->languageFactory->get('dav')->t('Accounts'),
			];
		} elseif ($prefix === 'principals/shares') {
			return [
				'uri' => 'principals/shares/' . $name,
				'{DAV:}displayname' => $name,
			];
		}
		return null;
	}

	/**
	 * Returns the list of groups a principal is a member of
	 *
	 * @param string $principal
	 * @param bool $needGroups
	 * @return array
	 * @throws Exception
	 */
	public function getGroupMembership($principal, $needGroups = false) {
		[$prefix, $name] = \Sabre\Uri\split($principal);

		if ($prefix !== $this->principalPrefix) {
			return [];
		}

		$user = $this->userManager->get($name);
		if (!$user) {
			throw new Exception('Principal not found');
		}

		$groups = [];

		if ($this->hasGroups || $needGroups) {
			$userGroups = $this->groupManager->getUserGroups($user);
			foreach ($userGroups as $userGroup) {
				if ($userGroup->hideFromCollaboration()) {
					continue;
				}
				$groups[] = 'principals/groups/' . urlencode($userGroup->getGID());
			}
		}

		$groups = array_unique(array_merge(
			$groups,
			$this->traitGetGroupMembership($principal, $needGroups)
		));

		return $groups;
	}

	/**
	 * @param string $path
	 * @param PropPatch $propPatch
	 * @return int
	 */
	public function updatePrincipal($path, PropPatch $propPatch) {
		// Updating schedule-default-calendar-URL is handled in CustomPropertiesBackend
		return 0;
	}

	/**
	 * Search user principals
	 *
	 * @param array $searchProperties
	 * @param string $test
	 * @return array
	 */
	protected function searchUserPrincipals(array $searchProperties, $test = 'allof') {
		$results = [];

		// If sharing is disabled, return the empty array
		$shareAPIEnabled = $this->shareManager->shareApiEnabled();
		if (!$shareAPIEnabled) {
			return [];
		}

		$allowEnumeration = $this->shareManager->allowEnumeration();
		$limitEnumerationGroup = $this->shareManager->limitEnumerationToGroups();
		$limitEnumerationPhone = $this->shareManager->limitEnumerationToPhone();
		$allowEnumerationFullMatch = $this->shareManager->allowEnumerationFullMatch();
		$ignoreSecondDisplayName = $this->shareManager->ignoreSecondDisplayName();
		$matchEmail = $this->shareManager->matchEmail();

		// If sharing is restricted to group members only,
		// return only members that have groups in common
		$restrictGroups = false;
		$currentUser = $this->userSession->getUser();
		if ($this->shareManager->shareWithGroupMembersOnly()) {
			if (!$currentUser instanceof IUser) {
				return [];
			}

			$restrictGroups = $this->groupManager->getUserGroupIds($currentUser);
		}

		$currentUserGroups = [];
		if ($limitEnumerationGroup) {
			if ($currentUser instanceof IUser) {
				$currentUserGroups = $this->groupManager->getUserGroupIds($currentUser);
			}
		}

		$searchLimit = $this->config->getSystemValueInt('sharing.maxAutocompleteResults', Constants::SHARING_MAX_AUTOCOMPLETE_RESULTS_DEFAULT);
		if ($searchLimit <= 0) {
			$searchLimit = null;
		}
		foreach ($searchProperties as $prop => $value) {
			switch ($prop) {
				case '{http://sabredav.org/ns}email-address':
					if (!$allowEnumeration) {
						if ($allowEnumerationFullMatch && $matchEmail) {
							$users = $this->userManager->getByEmail($value);
						} else {
							$users = [];
						}
					} else {
						$users = $this->userManager->getByEmail($value);
						$users = \array_filter($users, function (IUser $user) use ($currentUser, $value, $limitEnumerationPhone, $limitEnumerationGroup, $allowEnumerationFullMatch, $currentUserGroups) {
							if ($allowEnumerationFullMatch && $user->getSystemEMailAddress() === $value) {
								return true;
							}

							if ($limitEnumerationPhone
								&& $currentUser instanceof IUser
								&& $this->knownUserService->isKnownToUser($currentUser->getUID(), $user->getUID())) {
								// Synced phonebook match
								return true;
							}

							if (!$limitEnumerationGroup) {
								// No limitation on enumeration, all allowed
								return true;
							}

							return !empty($currentUserGroups) && !empty(array_intersect(
								$this->groupManager->getUserGroupIds($user),
								$currentUserGroups
							));
						});
					}

					$results[] = array_reduce($users, function (array $carry, IUser $user) use ($restrictGroups) {
						// is sharing restricted to groups only?
						if ($restrictGroups !== false) {
							$userGroups = $this->groupManager->getUserGroupIds($user);
							if (count(array_intersect($userGroups, $restrictGroups)) === 0) {
								return $carry;
							}
						}

						$carry[] = $this->principalPrefix . '/' . $user->getUID();
						return $carry;
					}, []);
					break;

				case '{DAV:}displayname':

					if (!$allowEnumeration) {
						if ($allowEnumerationFullMatch) {
							$lowerSearch = strtolower($value);
							$users = $this->userManager->searchDisplayName($value, $searchLimit);
							$users = \array_filter($users, static function (IUser $user) use ($lowerSearch, $ignoreSecondDisplayName) {
								$lowerDisplayName = strtolower($user->getDisplayName());
								return $lowerDisplayName === $lowerSearch || ($ignoreSecondDisplayName && trim(preg_replace('/ \(.*\)$/', '', $lowerDisplayName)) === $lowerSearch);
							});
						} else {
							$users = [];
						}
					} else {
						$users = $this->userManager->searchDisplayName($value, $searchLimit);
						$users = \array_filter($users, function (IUser $user) use ($currentUser, $value, $limitEnumerationPhone, $limitEnumerationGroup, $allowEnumerationFullMatch, $currentUserGroups) {
							if ($allowEnumerationFullMatch && $user->getDisplayName() === $value) {
								return true;
							}

							if ($limitEnumerationPhone
								&& $currentUser instanceof IUser
								&& $this->knownUserService->isKnownToUser($currentUser->getUID(), $user->getUID())) {
								// Synced phonebook match
								return true;
							}

							if (!$limitEnumerationGroup) {
								// No limitation on enumeration, all allowed
								return true;
							}

							return !empty($currentUserGroups) && !empty(array_intersect(
								$this->groupManager->getUserGroupIds($user),
								$currentUserGroups
							));
						});
					}

					$results[] = array_reduce($users, function (array $carry, IUser $user) use ($restrictGroups) {
						// is sharing restricted to groups only?
						if ($restrictGroups !== false) {
							$userGroups = $this->groupManager->getUserGroupIds($user);
							if (count(array_intersect($userGroups, $restrictGroups)) === 0) {
								return $carry;
							}
						}

						$carry[] = $this->principalPrefix . '/' . $user->getUID();
						return $carry;
					}, []);
					break;

				case '{urn:ietf:params:xml:ns:caldav}calendar-user-address-set':
					// If you add support for more search properties that qualify as a user-address,
					// please also add them to the array below
					$results[] = $this->searchUserPrincipals([
						// In theory this should also search for principal:principals/users/...
						// but that's used internally only anyway and i don't know of any client querying that
						'{http://sabredav.org/ns}email-address' => $value,
					], 'anyof');
					break;

				default:
					$results[] = [];
					break;
			}
		}

		// results is an array of arrays, so this is not the first search result
		// but the results of the first searchProperty
		if (count($results) === 1) {
			return $results[0];
		}

		switch ($test) {
			case 'anyof':
				return array_values(array_unique(array_merge(...$results)));

			case 'allof':
			default:
				return array_values(array_intersect(...$results));
		}
	}

	/**
	 * @param string $prefixPath
	 * @param array $searchProperties
	 * @param string $test
	 * @return array
	 */
	public function searchPrincipals($prefixPath, array $searchProperties, $test = 'allof') {
		if (count($searchProperties) === 0) {
			return [];
		}

		switch ($prefixPath) {
			case 'principals/users':
				return $this->searchUserPrincipals($searchProperties, $test);

			default:
				return [];
		}
	}

	/**
	 * @param string $uri
	 * @param string $principalPrefix
	 * @return string
	 */
	public function findByUri($uri, $principalPrefix) {
		// If sharing is disabled, return the empty array
		$shareAPIEnabled = $this->shareManager->shareApiEnabled();
		if (!$shareAPIEnabled) {
			return null;
		}

		// If sharing is restricted to group members only,
		// return only members that have groups in common
		$restrictGroups = false;
		if ($this->shareManager->shareWithGroupMembersOnly()) {
			$user = $this->userSession->getUser();
			if (!$user) {
				return null;
			}

			$restrictGroups = $this->groupManager->getUserGroupIds($user);
		}

		if (str_starts_with($uri, 'mailto:')) {
			if ($principalPrefix === 'principals/users') {
				$users = $this->userManager->getByEmail(substr($uri, 7));
				if (count($users) !== 1) {
					return null;
				}
				$user = $users[0];

				if ($restrictGroups !== false) {
					$userGroups = $this->groupManager->getUserGroupIds($user);
					if (count(array_intersect($userGroups, $restrictGroups)) === 0) {
						return null;
					}
				}

				return $this->principalPrefix . '/' . $user->getUID();
			}
		}
		if (str_starts_with($uri, 'principal:')) {
			$principal = substr($uri, 10);
			$principal = $this->getPrincipalByPath($principal);
			if ($principal !== null) {
				return $principal['uri'];
			}
		}

		return null;
	}

	/**
	 * @param IUser $user
	 * @return array
	 * @throws PropertyDoesNotExistException
	 */
	protected function userToPrincipal($user) {
		$userId = $user->getUID();
		$displayName = $user->getDisplayName();
		$principal = [
			'uri' => $this->principalPrefix . '/' . $userId,
			'{DAV:}displayname' => is_null($displayName) ? $userId : $displayName,
			'{urn:ietf:params:xml:ns:caldav}calendar-user-type' => 'INDIVIDUAL',
			'{http://nextcloud.com/ns}language' => $this->languageFactory->getUserLanguage($user),
		];

		$account = $this->accountManager->getAccount($user);
		$alternativeEmails = array_map(fn (IAccountProperty $property) => 'mailto:' . $property->getValue(), $account->getPropertyCollection(IAccountManager::COLLECTION_EMAIL)->getProperties());

		$email = $user->getSystemEMailAddress();
		if (!empty($email)) {
			$principal['{http://sabredav.org/ns}email-address'] = $email;
		}

		if (!empty($alternativeEmails)) {
			$principal['{DAV:}alternate-URI-set'] = $alternativeEmails;
		}

		return $principal;
	}

	public function getPrincipalPrefix() {
		return $this->principalPrefix;
	}

	/**
	 * @param string $circleUniqueId
	 * @return array|null
	 */
	protected function circleToPrincipal($circleUniqueId) {
		if (!$this->appManager->isEnabledForUser('circles') || !class_exists('\OCA\Circles\Api\v1\Circles')) {
			return null;
		}

		try {
			$circle = Circles::detailsCircle($circleUniqueId, true);
		} catch (QueryException $ex) {
			return null;
		} catch (CircleNotFoundException $ex) {
			return null;
		}

		if (!$circle) {
			return null;
		}

		$principal = [
			'uri' => 'principals/circles/' . $circleUniqueId,
			'{DAV:}displayname' => $circle->getDisplayName(),
		];

		return $principal;
	}

	/**
	 * Returns the list of circles a principal is a member of
	 *
	 * @param string $principal
	 * @return array
	 * @throws Exception
	 * @throws QueryException
	 * @suppress PhanUndeclaredClassMethod
	 */
	public function getCircleMembership($principal):array {
		if (!$this->appManager->isEnabledForUser('circles') || !class_exists('\OCA\Circles\Api\v1\Circles')) {
			return [];
		}

		[$prefix, $name] = \Sabre\Uri\split($principal);
		if ($this->hasCircles && $prefix === $this->principalPrefix) {
			$user = $this->userManager->get($name);
			if (!$user) {
				throw new Exception('Principal not found');
			}

			$circles = Circles::joinedCircles($name, true);

			$circles = array_map(function ($circle) {
				/** @var Circle $circle */
				return 'principals/circles/' . urlencode($circle->getSingleId());
			}, $circles);

			return $circles;
		}

		return [];
	}

	/**
	 * Get all email addresses associated to a principal.
	 *
	 * @param array $principal Data from getPrincipal*()
	 * @return string[] All email addresses without the mailto: prefix
	 */
	public function getEmailAddressesOfPrincipal(array $principal): array {
		$emailAddresses = [];

		if (isset($principal['{http://sabredav.org/ns}email-address'])) {
			$emailAddresses[] = $principal['{http://sabredav.org/ns}email-address'];
		}

		if (isset($principal['{DAV:}alternate-URI-set'])) {
			foreach ($principal['{DAV:}alternate-URI-set'] as $address) {
				if (str_starts_with($address, 'mailto:')) {
					$emailAddresses[] = substr($address, 7);
				}
			}
		}

		if (isset($principal['{urn:ietf:params:xml:ns:caldav}calendar-user-address-set'])) {
			foreach ($principal['{urn:ietf:params:xml:ns:caldav}calendar-user-address-set'] as $address) {
				if (str_starts_with($address, 'mailto:')) {
					$emailAddresses[] = substr($address, 7);
				}
			}
		}

		if (isset($principal['{http://calendarserver.org/ns/}email-address-set'])) {
			foreach ($principal['{http://calendarserver.org/ns/}email-address-set'] as $address) {
				if (str_starts_with($address, 'mailto:')) {
					$emailAddresses[] = substr($address, 7);
				}
			}
		}

		return array_values(array_unique($emailAddresses));
	}
}
