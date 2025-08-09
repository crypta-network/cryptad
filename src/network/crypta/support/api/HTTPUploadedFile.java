package network.crypta.support.api;

public interface HTTPUploadedFile {

	/**
	 * Returns the MIME type of the file.
	 * 
	 * @return The MIME type of the file
	 */
    String getContentType();

	/**
	 * Returns the data of the file.
	 * 
	 * @return The data of the file
	 */
    Bucket getData();

	/**
	 * Returns the name of the file.
	 * 
	 * @return The name of the file
	 */
    String getFilename();

}