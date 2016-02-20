// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Unit tests for CNode::ReceiveMsgBytes
//


#include "main.h"
#include "net.h"
#include "pow.h"
#include "serialize.h"
#include "timedata.h"
#include "util.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(ReceiveMsgBytes_tests)

BOOST_AUTO_TEST_CASE(FullMessages)
{
    CNode testNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), NODE_NETWORK));
    testNode.nVersion = 1;

    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << CMessageHeader("ping", 0);
    s << (uint64_t)11; // ping nonce
    CNetMessage::FinalizeHeader(s);

    LOCK(testNode.cs_vRecvMsg);

    // Receive a full 'ping' message
    {
        BOOST_CHECK(testNode.ReceiveMsgBytes(&s[0], s.size()));
        BOOST_CHECK_EQUAL(testNode.vRecvMsg.size(),1UL);
        CNetMessage& msg = testNode.vRecvMsg[0];
        BOOST_CHECK(msg.complete());
        BOOST_CHECK_EQUAL(msg.hdr.GetCommand(), "ping");
        uint64_t nonce;
        msg.vRecv >> nonce;
        BOOST_CHECK_EQUAL(nonce, (uint64_t)11);
    }


    testNode.vRecvMsg.clear();

    // ...receive it one byte at a time:
    {
        for (size_t i = 0; i < s.size(); i++) {
            BOOST_CHECK(testNode.ReceiveMsgBytes(&s[i], 1));
        }
        BOOST_CHECK_EQUAL(testNode.vRecvMsg.size(),1UL);
        CNetMessage& msg = testNode.vRecvMsg[0];
        BOOST_CHECK(msg.complete());
        BOOST_CHECK_EQUAL(msg.hdr.GetCommand(), "ping");
        uint64_t nonce;
        msg.vRecv >> nonce;
        BOOST_CHECK_EQUAL(nonce, (uint64_t)11);
   }
}

BOOST_AUTO_TEST_CASE(TooLargeBlock)
{
    // Random real block with four txs
    CBlock block;
    CDataStream stream(ParseHex("0100000075616236cc2126035fadb38deb65b9102cc2c41c09cdf29fc051906800000000fe7d5e12ef0ff901f6050211249919b1c0653771832b3a80c66cea42847f0ae1d4d26e49ffff001d00f0a4410401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d029105ffffffff0100f2052a010000004341046d8709a041d34357697dfcb30a9d05900a6294078012bf3bb09c6f9b525f1d16d5503d7905db1ada9501446ea00728668fc5719aa80be2fdfc8a858a4dbdd4fbac00000000010000000255605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d28350000000049483045022100aa46504baa86df8a33b1192b1b9367b4d729dc41e389f2c04f3e5c7f0559aae702205e82253a54bf5c4f65b7428551554b2045167d6d206dfe6a2e198127d3f7df1501ffffffff55605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d2835010000004847304402202329484c35fa9d6bb32a55a70c0982f606ce0e3634b69006138683bcd12cbb6602200c28feb1e2555c3210f1dddb299738b4ff8bbe9667b68cb8764b5ac17b7adf0001ffffffff0200e1f505000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac0000000001000000025f9a06d3acdceb56be1bfeaa3e8a25e62d182fa24fefe899d1c17f1dad4c2028000000004847304402205d6058484157235b06028c30736c15613a28bdb768ee628094ca8b0030d4d6eb0220328789c9a2ec27ddaec0ad5ef58efded42e6ea17c2e1ce838f3d6913f5e95db601ffffffff5f9a06d3acdceb56be1bfeaa3e8a25e62d182fa24fefe899d1c17f1dad4c2028010000004a493046022100c45af050d3cea806cedd0ab22520c53ebe63b987b8954146cdca42487b84bdd6022100b9b027716a6b59e640da50a864d6dd8a0ef24c76ce62391fa3eabaf4d2886d2d01ffffffff0200e1f505000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac000000000100000002e2274e5fea1bf29d963914bd301aa63b64daaf8a3e88f119b5046ca5738a0f6b0000000048473044022016e7a727a061ea2254a6c358376aaa617ac537eb836c77d646ebda4c748aac8b0220192ce28bf9f2c06a6467e6531e27648d2b3e2e2bae85159c9242939840295ba501ffffffffe2274e5fea1bf29d963914bd301aa63b64daaf8a3e88f119b5046ca5738a0f6b010000004a493046022100b7a1a755588d4190118936e15cd217d133b0e4a53c3c15924010d5648d8925c9022100aaef031874db2114f2d869ac2de4ae53908fbfea5b2b1862e181626bb9005c9f01ffffffff0200e1f505000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00000000"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CNode testNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), NODE_NETWORK));
    testNode.nVersion = 1;

    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << CMessageHeader("block", 0);
    size_t headerLen = s.size();
    s << block;

    // Test: too large
    size_t maxBlockSize = Params().MaxBlockSize(GetAdjustedTime(), sizeForkTime.load());
    s.resize(maxBlockSize+headerLen+1);
    CNetMessage::FinalizeHeader(s);

    BOOST_CHECK(!testNode.ReceiveMsgBytes(&s[0], s.size()));

    testNode.vRecvMsg.clear();

    // Test: exactly at max:
    s.resize(maxBlockSize+headerLen);
    CNetMessage::FinalizeHeader(s);

    BOOST_CHECK(testNode.ReceiveMsgBytes(&s[0], s.size()));
}

BOOST_AUTO_TEST_CASE(TooLargeVerack)
{
    CNode testNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), NODE_NETWORK));
    testNode.nVersion = 1;

    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << CMessageHeader("verack", 0);
    size_t headerLen = s.size();

    CNetMessage::FinalizeHeader(s);
    BOOST_CHECK(testNode.ReceiveMsgBytes(&s[0], s.size()));

    // verack is zero-length, so even one byte bigger is too big:
    s.resize(headerLen+1);
    CNetMessage::FinalizeHeader(s);
    BOOST_CHECK(testNode.ReceiveMsgBytes(&s[0], s.size()));
    CNodeStateStats stats;
    GetNodeStateStats(testNode.GetId(), stats);
    BOOST_CHECK(stats.nMisbehavior > 0);
}

BOOST_AUTO_TEST_CASE(TooLargePing)
{
    CNode testNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), NODE_NETWORK));
    testNode.nVersion = 1;

    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << CMessageHeader("ping", 0);
    s << (uint64_t)11; // 8-byte nonce

    CNetMessage::FinalizeHeader(s);
    BOOST_CHECK(testNode.ReceiveMsgBytes(&s[0], s.size()));

    // Add another nonce, sanity check should fail
    s << (uint64_t)11; // 8-byte nonce
    CNetMessage::FinalizeHeader(s);
    BOOST_CHECK(testNode.ReceiveMsgBytes(&s[0], s.size()));
    CNodeStateStats stats;
    GetNodeStateStats(testNode.GetId(), stats);
    BOOST_CHECK(stats.nMisbehavior > 0);
}

BOOST_AUTO_TEST_SUITE_END()
