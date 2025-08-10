package network.crypta.node;

import java.net.MalformedURLException;

import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertBlock;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.RequestClient;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.RandomAccessBucket;

public class NodeAndClientLayerTestBase {

    static final int PORT = 2048;
    static final int FILE_SIZE = 1024*1024;
    
    static RequestClient rc = new RequestClient() {

        @Override
        public boolean persistent() {
            return false;
        }

        @Override
        public boolean realTimeFlag() {
            return false;
        }
        
    };
    
    protected InsertBlock generateBlock(DummyRandomSource random, boolean createUsk) throws MalformedURLException {
        byte[] data = new byte[FILE_SIZE];
        random.nextBytes(data);
        RandomAccessBucket bucket = new SimpleReadOnlyArrayBucket(data);
        FreenetURI uri = InsertableClientSSK.createRandom(random, "test").getInsertURI();
        if (createUsk) {
            uri = uri.setDocName("foo-0");
            uri = uri.uskForSSK();
            uri = uri.setSuggestedEdition(-1);
        }
        return new InsertBlock(bucket, new ClientMetadata(null), uri);
    }
    
}
