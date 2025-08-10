package network.crypta.support.io;

import java.io.IOException;

import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

public class NullBucketFactory implements BucketFactory {

	@Override
	public RandomAccessBucket makeBucket(long size) throws IOException {
		return new NullBucket();
	}

}
