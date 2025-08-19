package network.crypta.client.async;

import network.crypta.crypt.HashResult;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

record CompressionOutput(RandomAccessBucket data, COMPRESSOR_TYPE bestCodec, HashResult[] hashes) {

}
