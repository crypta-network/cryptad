package network.crypta.client.filter;

import java.nio.ByteBuffer;

public abstract class FlacPacket extends CodecPacket {

	FlacPacket(byte[] payload) {
		super(payload);
	}
}

class FlacMetadataBlock extends FlacPacket {
	enum BlockType {STREAMINFO, PADDING, APPLICATION, SEEKTABLE, VORBIS_COMMENT,
		CUESHEET, PICTURE, UNKNOWN, INVALID}
	private final FlacMetadataBlockHeader header = new FlacMetadataBlockHeader();

	FlacMetadataBlock(int header, byte[] payload) {
		super(payload);
		this.header.lastMetadataBlock = ((header & 0x80000000) >>> 31) == 1;
		this.header.block_type = (byte) ((header & 0x7F000000) >>> 24);
		this.header.length = (header & 0x00FFFFFF);
	}

	@Override
	public byte[] toArray() {
		ByteBuffer bb = ByteBuffer.allocate(getLength());
		bb.putInt(header.toInt());
		bb.put(payload);
		return bb.array();
	}

	public boolean isLastMetadataBlock() {
		return header.lastMetadataBlock;
	}

	public BlockType getMetadataBlockType() {
		return switch(header.block_type) {
		case 0 -> BlockType.STREAMINFO;
		case 1 -> BlockType.PADDING;
		case 2 -> BlockType.APPLICATION;
		case 3 -> BlockType.SEEKTABLE;
		case 4 -> BlockType.VORBIS_COMMENT;
		case 5 -> BlockType.CUESHEET;
		case 6 -> BlockType.PICTURE;
		case 127 -> BlockType.INVALID;
		default -> BlockType.UNKNOWN;
		};
	}

	public void setMetadataBlockType(BlockType type) {
		switch(type) {
		case STREAMINFO:
			this.header.block_type = 0;
			break;
		case PADDING:
			this.header.block_type = 1;
			break;
		case APPLICATION:
			this.header.block_type = 2;
			break;
		case SEEKTABLE:
			this.header.block_type = 3;
			break;
		case VORBIS_COMMENT:
			this.header.block_type = 4;
			break;
		case CUESHEET:
			this.header.block_type = 5;
			break;
		case PICTURE:
			this.header.block_type = 6;
			break;
		}
	}

	public FlacMetadataBlockHeader getHeader() {
		FlacMetadataBlockHeader newHeader = new FlacMetadataBlockHeader();
		newHeader.lastMetadataBlock = this.header.lastMetadataBlock;
		newHeader.block_type = this.header.block_type;
		newHeader.length = this.header.length;
		return newHeader;
	}

	public int getLength() {
		return 4+header.length;
	}

	class FlacMetadataBlockHeader {
		boolean lastMetadataBlock;
		byte block_type;
		int length;

		public int toInt() {
			return ((lastMetadataBlock ? 1 : 0) << 31) | (block_type << 24) | length;
		}
	}
}

class FlacFrame extends FlacPacket {

	FlacFrame(byte[] payload) {
		super(payload);
	}
}
