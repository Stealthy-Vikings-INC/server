<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace NCU\Config\Exceptions;

use Exception;

/**
 * @experimental 31.0.0
 * @deprecated 32.0.0  use \OCP\Config\Exceptions\IncorrectTypeException
 * @see \OCP\Config\Exceptions\IncorrectTypeException
 */
class IncorrectTypeException extends Exception {
}
