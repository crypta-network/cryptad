package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;

import network.crypta.clients.fcp.FCPConnectionHandler.DDACheckJob;
import network.crypta.node.Node;
import network.crypta.support.Logger;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;

/**
 * client -> node: DDARequest { WantRead=true, WantWrite=true, Dir=/tmp/blah }
 * node -> client: DDAReply { Dir=/tmp/blah, ReadFilename=random1, WriteFilename=random2, ContentToWrite=random3 }
 * client -> node: DDAResponse { Dir=/tmp/blah, ReadContent=blah }
 * node -> client: DDAComplete { Dir=/tmp/blah, ReadAllowed=true, WriteAllowed=true }
 * 
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 *
 */
public class TestDDACompleteMessage extends FCPMessage {
	public final static String name = "TestDDAComplete";
	public final static String READ_ALLOWED = "ReadDirectoryAllowed";
	public final static String WRITE_ALLOWED = "WriteDirectoryAllowed";

	final DDACheckJob checkJob;
	final String readContentFromClient;
	private final FCPConnectionHandler handler;
	
	public TestDDACompleteMessage(FCPConnectionHandler handler, DDACheckJob job, String readContent) {
		this.checkJob = job;
		this.readContentFromClient = readContent;
		this.handler = handler;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet sfs = new SimpleFieldSet(true);
		
		sfs.putSingle(TestDDARequestMessage.DIRECTORY, checkJob.directory.toString());
		
		boolean isReadAllowed = false; 
		boolean isWriteAllowed = false;
		
		if(checkJob.readFilename != null) {
			isReadAllowed = (checkJob.readContent.equals(readContentFromClient));
			// cleanup in any case : we created it!... let's hope the client will do the same on its side.
			checkJob.readFilename.delete();
			sfs.putSingle(READ_ALLOWED, String.valueOf(isReadAllowed));
		}
		
		if(checkJob.writeFilename != null) {
			File maybeWrittenFile = checkJob.writeFilename;
			if (maybeWrittenFile.exists() && maybeWrittenFile.isFile() && maybeWrittenFile.canRead()) {
				try {
				    String existingContent = FileUtil.readUTF(maybeWrittenFile).toString().trim();
					isWriteAllowed = checkJob.writeContent.equals(existingContent);
				} catch (IOException e) {
					Logger.error(this, "Caught an IOE trying to read the file (" + maybeWrittenFile + ")! " + e.getMessage());
				}
			}
			sfs.putSingle(WRITE_ALLOWED, String.valueOf(isWriteAllowed));
		}
		
		// FIXME this really shouldn't be a side-effect!
		handler.registerTestDDAResult(checkJob.directory.toString(), isReadAllowed, isWriteAllowed);
		
		return sfs;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, name + " goes from server to client not the other way around", name, false);
	}
}
