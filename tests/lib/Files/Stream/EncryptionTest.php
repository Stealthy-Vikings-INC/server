<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2016-2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2016 ownCloud, Inc.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
namespace Test\Files\Stream;

use OC\Encryption\File;
use OC\Encryption\Util;
use OC\Files\Cache\CacheEntry;
use OC\Files\Storage\Storage;
use OC\Files\Storage\Wrapper\Wrapper;
use OC\Files\Stream\Encryption;
use OC\Files\View;
use OC\Memcache\ArrayCache;
use OCP\Encryption\IEncryptionModule;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\Cache\ICache;
use OCP\ICacheFactory;
use OCP\IConfig;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

class EncryptionTest extends \Test\TestCase {
	public const DEFAULT_WRAPPER = '\OC\Files\Stream\Encryption';

	private IEncryptionModule&MockObject $encryptionModule;

	/**
	 * @param class-string<Wrapper> $wrapper
	 * @return resource
	 */
	protected function getStream(string $fileName, string $mode, int $unencryptedSize, string $wrapper = self::DEFAULT_WRAPPER, int $unencryptedSizeOnClose = 0) {
		clearstatcache();
		$size = filesize($fileName);
		$source = fopen($fileName, $mode);
		$internalPath = $fileName;
		$fullPath = $fileName;
		$header = [];
		$uid = '';
		$this->encryptionModule = $this->buildMockModule();
		$cache = $this->createMock(ICache::class);
		$storage = $this->getMockBuilder('\OC\Files\Storage\Storage')
			->disableOriginalConstructor()->getMock();
		$encStorage = $this->getMockBuilder('\OC\Files\Storage\Wrapper\Encryption')
			->disableOriginalConstructor()->getMock();
		$config = $this->getMockBuilder(IConfig::class)
			->disableOriginalConstructor()
			->getMock();
		$arrayCache = $this->createMock(ArrayCache::class);
		$groupManager = $this->getMockBuilder('\OC\Group\Manager')
			->disableOriginalConstructor()
			->getMock();
		$file = $this->getMockBuilder('\OC\Encryption\File')
			->disableOriginalConstructor()
			->onlyMethods(['getAccessList'])
			->getMock();
		$file->expects($this->any())->method('getAccessList')->willReturn([]);
		$util = $this->getMockBuilder('\OC\Encryption\Util')
			->onlyMethods(['getUidAndFilename'])
			->setConstructorArgs([new View(), new \OC\User\Manager(
				$config,
				$this->createMock(ICacheFactory::class),
				$this->createMock(IEventDispatcher::class),
				$this->createMock(LoggerInterface::class),
			), $groupManager, $config, $arrayCache])
			->getMock();
		$util->expects($this->any())
			->method('getUidAndFilename')
			->willReturn(['user1', $internalPath]);
		$storage->expects($this->any())->method('getCache')->willReturn($cache);
		$entry = new CacheEntry([
			'fileid' => 5,
			'encryptedVersion' => 2,
			'unencrypted_size' => $unencryptedSizeOnClose,
		]);
		$cache->expects($this->any())->method('get')->willReturn($entry);
		$cache->expects($this->any())->method('update')->with(5, ['encrypted' => 3, 'encryptedVersion' => 3, 'unencrypted_size' => $unencryptedSizeOnClose]);

		return $wrapper::wrap(
			$source,
			$internalPath,
			$fullPath,
			$header,
			$uid,
			$this->encryptionModule,
			$storage,
			$encStorage,
			$util,
			$file,
			$mode,
			$size,
			$unencryptedSize,
			8192,
			true,
			$wrapper,
		);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dataProviderStreamOpen')]
	public function testStreamOpen(
		$isMasterKeyUsed,
		$mode,
		$fullPath,
		$fileExists,
		$expectedSharePath,
		$expectedSize,
		$expectedUnencryptedSize,
		$expectedReadOnly,
	): void {
		// build mocks
		$encryptionModuleMock = $this->createMock(IEncryptionModule::class);
		$encryptionModuleMock->expects($this->any())->method('needDetailedAccessList')->willReturn(!$isMasterKeyUsed);
		$encryptionModuleMock->expects($this->once())
			->method('getUnencryptedBlockSize')->willReturn(99);
		$encryptionModuleMock->expects($this->once())
			->method('begin')->willReturn([]);

		$storageMock = $this->createMock(Storage::class);
		$storageMock->expects($this->once())->method('file_exists')->willReturn($fileExists);

		$fileMock = $this->createMock(File::class);
		if ($isMasterKeyUsed) {
			$fileMock->expects($this->never())->method('getAccessList');
		} else {
			$fileMock->expects($this->once())->method('getAccessList')
				->willReturnCallback(function ($sharePath) use ($expectedSharePath) {
					$this->assertSame($expectedSharePath, $sharePath);
					return [];
				});
		}
		$utilMock = $this->getMockBuilder(Util::class)
			->disableOriginalConstructor()->getMock();
		$utilMock->expects($this->any())
			->method('getHeaderSize')
			->willReturn(8192);

		// get a instance of the stream wrapper
		$streamWrapper = $this->getMockBuilder(Encryption::class)
			->onlyMethods(['loadContext', 'writeHeader', 'skipHeader'])
			->disableOriginalConstructor()
			->getMock();

		// set internal properties of the stream wrapper
		$stream = new \ReflectionClass(Encryption::class);
		$encryptionModule = $stream->getProperty('encryptionModule');
		$encryptionModule->setAccessible(true);
		$encryptionModule->setValue($streamWrapper, $encryptionModuleMock);
		$encryptionModule->setAccessible(false);
		$storage = $stream->getProperty('storage');
		$storage->setAccessible(true);
		$storage->setValue($streamWrapper, $storageMock);
		$storage->setAccessible(false);
		$file = $stream->getProperty('file');
		$file->setAccessible(true);
		$file->setValue($streamWrapper, $fileMock);
		$file->setAccessible(false);
		$util = $stream->getProperty('util');
		$util->setAccessible(true);
		$util->setValue($streamWrapper, $utilMock);
		$util->setAccessible(false);
		$fullPathP = $stream->getProperty('fullPath');
		$fullPathP->setAccessible(true);
		$fullPathP->setValue($streamWrapper, $fullPath);
		$fullPathP->setAccessible(false);
		$header = $stream->getProperty('header');
		$header->setAccessible(true);
		$header->setValue($streamWrapper, []);
		$header->setAccessible(false);
		$this->invokePrivate($streamWrapper, 'signed', [true]);
		$this->invokePrivate($streamWrapper, 'internalPath', [$fullPath]);
		$this->invokePrivate($streamWrapper, 'uid', ['test']);

		// call stream_open, that's the method we want to test
		$dummyVar = 'foo';
		$streamWrapper->stream_open('', $mode, '', $dummyVar);

		// check internal properties
		$size = $stream->getProperty('size');
		$size->setAccessible(true);
		$this->assertSame($expectedSize, $size->getValue($streamWrapper));
		$size->setAccessible(false);

		$unencryptedSize = $stream->getProperty('unencryptedSize');
		$unencryptedSize->setAccessible(true);
		$this->assertSame($expectedUnencryptedSize, $unencryptedSize->getValue($streamWrapper));
		$unencryptedSize->setAccessible(false);

		$readOnly = $stream->getProperty('readOnly');
		$readOnly->setAccessible(true);
		$this->assertSame($expectedReadOnly, $readOnly->getValue($streamWrapper));
		$readOnly->setAccessible(false);
	}

	public static function dataProviderStreamOpen(): array {
		return [
			[false, 'r', '/foo/bar/test.txt', true, '/foo/bar/test.txt', null, null, true],
			[false, 'r', '/foo/bar/test.txt', false, '/foo/bar', null, null, true],
			[false, 'w', '/foo/bar/test.txt', true, '/foo/bar/test.txt', 8192, 0, false],
			[true, 'r', '/foo/bar/test.txt', true, '/foo/bar/test.txt', null, null, true],
			[true, 'r', '/foo/bar/test.txt', false, '/foo/bar', null, null, true],
			[true, 'w', '/foo/bar/test.txt', true, '/foo/bar/test.txt', 8192, 0, false],
		];
	}

	public function testWriteRead(): void {
		$fileName = tempnam('/tmp', 'FOO');
		$stream = $this->getStream($fileName, 'w+', 0, self::DEFAULT_WRAPPER, 6);
		$this->assertEquals(6, fwrite($stream, 'foobar'));
		fclose($stream);

		$stream = $this->getStream($fileName, 'r', 6);
		$this->assertEquals('foobar', fread($stream, 100));
		fclose($stream);

		$stream = $this->getStream($fileName, 'r+', 6, self::DEFAULT_WRAPPER, 6);
		$this->assertEquals(3, fwrite($stream, 'bar'));
		fclose($stream);

		$stream = $this->getStream($fileName, 'r', 6);
		$this->assertEquals('barbar', fread($stream, 100));
		fclose($stream);

		unlink($fileName);
	}

	public function testRewind(): void {
		$fileName = tempnam('/tmp', 'FOO');
		$stream = $this->getStream($fileName, 'w+', 0, self::DEFAULT_WRAPPER, 6);
		$this->assertEquals(6, fwrite($stream, 'foobar'));
		$this->assertEquals(true, rewind($stream));
		$this->assertEquals('foobar', fread($stream, 100));
		$this->assertEquals(true, rewind($stream));
		$this->assertEquals(3, fwrite($stream, 'bar'));
		fclose($stream);

		$stream = $this->getStream($fileName, 'r', 6);
		$this->assertEquals('barbar', fread($stream, 100));
		fclose($stream);

		unlink($fileName);
	}

	public function testSeek(): void {
		$fileName = tempnam('/tmp', 'FOO');

		$stream = $this->getStream($fileName, 'w+', 0, self::DEFAULT_WRAPPER, 9);
		$this->assertEquals(6, fwrite($stream, 'foobar'));
		$this->assertEquals(0, fseek($stream, 3));
		$this->assertEquals(6, fwrite($stream, 'foobar'));
		fclose($stream);

		$stream = $this->getStream($fileName, 'r', 9);
		$this->assertEquals('foofoobar', fread($stream, 100));
		$this->assertEquals(-1, fseek($stream, 10));
		$this->assertEquals(0, fseek($stream, 9));
		$this->assertEquals(-1, fseek($stream, -10, SEEK_CUR));
		$this->assertEquals(0, fseek($stream, -9, SEEK_CUR));
		$this->assertEquals(-1, fseek($stream, -10, SEEK_END));
		$this->assertEquals(0, fseek($stream, -9, SEEK_END));
		fclose($stream);

		unlink($fileName);
	}

	public static function dataFilesProvider(): array {
		return [
			['lorem-big.txt'],
			['block-aligned.txt'],
			['block-aligned-plus-one.txt'],
		];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('dataFilesProvider')]
	public function testWriteReadBigFile($testFile): void {
		$expectedData = file_get_contents(\OC::$SERVERROOT . '/tests/data/' . $testFile);
		// write it
		$fileName = tempnam('/tmp', 'FOO');
		$stream = $this->getStream($fileName, 'w+', 0, self::DEFAULT_WRAPPER, strlen($expectedData));
		// while writing the file from the beginning to the end we should never try
		// to read parts of the file. This should only happen for write operations
		// in the middle of a file
		$this->encryptionModule->expects($this->never())->method('decrypt');
		fwrite($stream, $expectedData);
		fclose($stream);

		// read it all
		$stream = $this->getStream($fileName, 'r', strlen($expectedData));
		$data = stream_get_contents($stream);
		fclose($stream);

		$this->assertEquals($expectedData, $data);

		// another read test with a loop like we do in several places:
		$stream = $this->getStream($fileName, 'r', strlen($expectedData));
		$data = '';
		while (!feof($stream)) {
			$data .= fread($stream, 8192);
		}
		fclose($stream);

		$this->assertEquals($expectedData, $data);

		unlink($fileName);
	}

	/**
	 * simulate a non-seekable storage
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('dataFilesProvider')]
	public function testWriteToNonSeekableStorage($testFile): void {
		$wrapper = $this->getMockBuilder(Encryption::class)
			->onlyMethods(['parentStreamSeek'])
			->getMock();
		$wrapper->expects($this->any())
			->method('parentStreamSeek')
			->willReturn(false);

		$expectedData = file_get_contents(\OC::$SERVERROOT . '/tests/data/' . $testFile);
		// write it
		$fileName = tempnam('/tmp', 'FOO');
		$stream = $this->getStream($fileName, 'w+', 0, '\Test\Files\Stream\DummyEncryptionWrapper', strlen($expectedData));
		// while writing the file from the beginning to the end we should never try
		// to read parts of the file. This should only happen for write operations
		// in the middle of a file
		$this->encryptionModule->expects($this->never())->method('decrypt');
		fwrite($stream, $expectedData);
		fclose($stream);

		// read it all
		$stream = $this->getStream($fileName, 'r', strlen($expectedData), '\Test\Files\Stream\DummyEncryptionWrapper', strlen($expectedData));
		$data = stream_get_contents($stream);
		fclose($stream);

		$this->assertEquals($expectedData, $data);

		// another read test with a loop like we do in several places:
		$stream = $this->getStream($fileName, 'r', strlen($expectedData));
		$data = '';
		while (!feof($stream)) {
			$data .= fread($stream, 8192);
		}
		fclose($stream);

		$this->assertEquals($expectedData, $data);

		unlink($fileName);
	}

	protected function buildMockModule(): IEncryptionModule&MockObject {
		$encryptionModule = $this->getMockBuilder(IEncryptionModule::class)
			->disableOriginalConstructor()
			->onlyMethods(['getId', 'getDisplayName', 'begin', 'end', 'encrypt', 'decrypt', 'update', 'shouldEncrypt', 'getUnencryptedBlockSize', 'isReadable', 'encryptAll', 'prepareDecryptAll', 'isReadyForUser', 'needDetailedAccessList'])
			->getMock();

		$encryptionModule->expects($this->any())->method('getId')->willReturn('UNIT_TEST_MODULE');
		$encryptionModule->expects($this->any())->method('getDisplayName')->willReturn('Unit test module');
		$encryptionModule->expects($this->any())->method('begin')->willReturn([]);
		$encryptionModule->expects($this->any())->method('end')->willReturn('');
		$encryptionModule->expects($this->any())->method('isReadable')->willReturn(true);
		$encryptionModule->expects($this->any())->method('needDetailedAccessList')->willReturn(false);
		$encryptionModule->expects($this->any())->method('encrypt')->willReturnCallback(function ($data) {
			// simulate different block size by adding some padding to the data
			if (isset($data[6125])) {
				return str_pad($data, 8192, 'X');
			}
			// last block
			return $data;
		});
		$encryptionModule->expects($this->any())->method('decrypt')->willReturnCallback(function ($data) {
			if (isset($data[8191])) {
				return substr($data, 0, 6126);
			}
			// last block
			return $data;
		});
		$encryptionModule->expects($this->any())->method('update')->willReturn(true);
		$encryptionModule->expects($this->any())->method('shouldEncrypt')->willReturn(true);
		$encryptionModule->expects($this->any())->method('getUnencryptedBlockSize')->willReturn(6126);
		return $encryptionModule;
	}
}
