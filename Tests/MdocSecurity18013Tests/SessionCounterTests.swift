/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import CryptoKit
import Testing
@testable import MdocSecurity18013

extension MdocSecurity18013Tests {
    @Test func copiedSessionsDoNotReuseAnEncryptionNonce() async throws {
        var (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        var copy = session
        let first = try #require(try await session.encrypt([1, 2, 3]))
        let second = try #require(try await copy.encrypt([1, 2, 3]))
        #expect(first != second)
        let key = try await session.makeKeyAgreementAndDeriveSessionKey(isEncrypt: true)
        let box = try AES.GCM.SealedBox(combined: session.makeNonce(2, isEncrypt: true) + second)
        #expect(try AES.GCM.open(box, using: key) == Data([1, 2, 3]))
    }

    @Test func receiveCountersAdvanceIndependentlyOfSendCounters() async throws {
        var (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        let readerKey = try await session.makeKeyAgreementAndDeriveSessionKey(isEncrypt: false)
        func incoming(_ counter: UInt32) throws -> [UInt8] {
            let box = try AES.GCM.seal(Data([UInt8(counter)]), using: readerKey, nonce: session.makeNonce(counter, isEncrypt: false))
            return Array(try #require(box.combined).dropFirst(12))
        }
        let first = try incoming(1)
        let second = try incoming(2)
        #expect(try await session.decrypt(first) == [1])
        #expect(try await session.decrypt(second) == [2])
        let outgoing = try #require(try await session.encrypt([3]))
        let deviceKey = try await session.makeKeyAgreementAndDeriveSessionKey(isEncrypt: true)
        let box = try AES.GCM.SealedBox(combined: session.makeNonce(1, isEncrypt: true) + outgoing)
        #expect(try AES.GCM.open(box, using: deviceKey) == Data([3]))
    }

    @Test func replayedCiphertextTerminatesAllCopies() async throws {
        var (establishment, session) = try #require(try makeSessionEncryptionFromAnnexData())
        var copy = session
        _ = try await session.decrypt(establishment.data)
        await #expect(throws: (any Error).self) { _ = try await copy.decrypt(establishment.data) }
        await #expect(throws: SessionEncryptionError.sessionTerminated) { _ = try await session.encrypt([0]) }
    }

    @Test func counterExhaustionNeverWraps() async throws {
        var (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        session.messageCounters.withLock { $0.encryption = UInt64(UInt32.max) }
        let cipher = try #require(try await session.encrypt([9]))
        let key = try await session.makeKeyAgreementAndDeriveSessionKey(isEncrypt: true)
        let box = try AES.GCM.SealedBox(combined: session.makeNonce(UInt32.max, isEncrypt: true) + cipher)
        #expect(try AES.GCM.open(box, using: key) == Data([9]))
        await #expect(throws: SessionEncryptionError.counterExhausted) { _ = try await session.encrypt([9]) }
        await #expect(throws: SessionEncryptionError.sessionTerminated) { _ = try await session.decrypt([0]) }
    }

    @Test func concurrentCopiesCannotReuseANonce() async throws {
        let (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        let ciphertexts = await withTaskGroup(of: [UInt8]?.self) { group in
            for _ in 0..<32 {
                group.addTask {
                    var copy = session
                    do { return try await copy.encrypt([1, 2, 3]) }
                    catch SessionEncryptionError.operationInProgress { return nil }
                    catch { Issue.record(error); return nil }
                }
            }
            var results = [[UInt8]]()
            for await cipher in group { if let cipher { results.append(cipher) } }
            return results
        }
        #expect(!ciphertexts.isEmpty)
        #expect(Set(ciphertexts).count == ciphertexts.count)
    }

    @Test func invalidationIsSharedByAllCopies() async throws {
        let (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        var copy = session
        session.invalidate()
        await #expect(throws: SessionEncryptionError.sessionTerminated) { _ = try await copy.encrypt([1]) }
    }

    @Test func cancelledEncryptionTerminatesAllCopies() async throws {
        var (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        let original = session
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            var copy = original
            return try await copy.encrypt([1])
        }
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        await #expect(throws: SessionEncryptionError.sessionTerminated) { _ = try await session.encrypt([1]) }
    }

    @Test func keyDerivationFailureTerminatesAllCopies() async throws {
        var (_, session) = try #require(try makeSessionEncryptionFromAnnexData())
        var copy = session
        session.sessionKeys = .init(publicKey: nil, privateKey: session.sessionKeys.privateKey)
        await #expect(throws: (any Error).self) { _ = try await session.encrypt([1]) }
        await #expect(throws: SessionEncryptionError.sessionTerminated) { _ = try await copy.encrypt([1]) }
    }
}
