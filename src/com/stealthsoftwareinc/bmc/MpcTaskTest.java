/*
 * Copyright (C) 2021 Stealth Software Technologies, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/*

# How to run this thing (adjust as needed):

# Work from the directory that contains the
# com/stealthsoftwareinc/bmc/MpcTaskTest.java file, i.e., work from the
# src directory.

# You need a local RabbitMQ server (localhost:5672).
# You need gmp, nettle, and bmc (Stealth) installed.

# You need amqp-client-5.7.3.jar and its dependencies:
(
  wget https://repo1.maven.org/maven2/com/rabbitmq/amqp-client/5.7.3/amqp-client-5.7.3.jar
  wget https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.26/slf4j-api-1.7.26.jar
  wget https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/1.7.26/slf4j-simple-1.7.26.jar
)

# You need these files too:
# coffeeshop_n_2.cbg
# coffeeshop_n_3.cbg

# First do this
(
  export CLASSPATH=.:*
  export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"
  javac com/stealthsoftwareinc/bmc/MpcTaskTest.java
)

# Run this to test two parties
(
  export CLASSPATH=.:*
  export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"
  java com.stealthsoftwareinc.bmc.MpcTaskTest \
    2 0 coffeeshop_n_2.cbg x0_lat=1,x0_lng=-1 \
  &
  java com.stealthsoftwareinc.bmc.MpcTaskTest \
    2 1 coffeeshop_n_2.cbg x1_lat=1,x1_lng=-1 \
  &
  wait
)
# It should print out "result: 2,-2" twice.

# Run this to test three parties
(
  export CLASSPATH=.:*
  export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"
  java com.stealthsoftwareinc.bmc.MpcTaskTest \
    3 0 coffeeshop_n_3.cbg x0_lat=1,x0_lng=-1 \
  &
  java com.stealthsoftwareinc.bmc.MpcTaskTest \
    3 1 coffeeshop_n_3.cbg x1_lat=1,x1_lng=-1 \
  &
  java com.stealthsoftwareinc.bmc.MpcTaskTest \
    3 2 coffeeshop_n_3.cbg x2_lat=1,x2_lng=-1 \
  &
  wait
)
# It should print out "result: 3,-3" three times.

*/

package com.stealthsoftwareinc.bmc;

/* begin_imports */

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import com.stealthsoftwareinc.bmc.MpcTask;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;

/* end_imports */

public final class MpcTaskTest
{

  private final static class MyChannel
  implements
    MpcTask.Channel
  {

    private final Channel channel;
    private final String sendQueue;

    public MyChannel(
      final Channel channel,
      final String sendQueue
    ) {
      this.channel = channel;
      this.sendQueue = sendQueue;
    }

    @Override
    public final void send(
      final byte[] buf
    ) throws
      IOException
    {
      channel.basicPublish("", sendQueue, null, buf);
    }

  }

  public static void main(
    final String... args
  ) throws
    Exception
  {

    System.loadLibrary("gmp");
    System.loadLibrary("nettle");
    System.loadLibrary("bmc");

    final ConnectionFactory factory = new ConnectionFactory();
    factory.setHost("localhost");

    try (
      final Connection connection = factory.newConnection();
      final Channel channel = connection.createChannel();
    ) {

      final int partyCount = Integer.parseInt(args[0]);
      final int partyIndex = Integer.parseInt(args[1]);
      final String circuitFile = args[2];
      final String inputString = args[3];

      final ArrayList<MpcTask.Channel> channels = new ArrayList<>();
      for (int i = 0; i != partyCount; ++i) {
        if (i == partyIndex) {
          channels.add(null);
        } else {
          final String sendQueue = partyIndex + "-" + i;
          final String recvQueue = i + "-" + partyIndex;
          channel.queueDeclare(sendQueue, false, false, true, null);
          channel.queueDeclare(recvQueue, false, false, true, null);
          channels.add(new MyChannel(channel, sendQueue));
        }
      }
      final MpcTask mpc =
        new MpcTask(
          circuitFile,
          inputString,
          channels,
          true
        )
      ;
      for (int i = 0; i != partyCount; ++i) {
        if (i != partyIndex) {
          final String recvQueue = i + "-" + partyIndex;
          final MpcTask.Channel c = channels.get(i);
          channel.basicConsume(
            recvQueue,
            new DefaultConsumer(channel) {
              @Override
              public final void handleDelivery(
                final String consumerTag,
                final Envelope envelope,
                final AMQP.BasicProperties properties,
                final byte[] body
              ) throws
                IOException
              {
                mpc.recv(c, body);
              }
            }
          );
        }
      }
      try {
        final String result = mpc.call();
        System.out.println("result: " + result);
        System.out.println("log:\n" + mpc.getLog());
      } catch (final Exception e) {
        System.out.println("error!");
        System.out.println("log:\n" + mpc.getLog());
        throw e;
      }

    }

  }

}
