package network.crypta.support.api;

public interface HTTPUploadedFile {

  /**
   * Returns the MIME type of the file.
   *
   * @return The MIME type of the file
   */
  String contentType();

  /**
   * Returns the data of the file.
   *
   * @return The data of the file
   */
  Bucket data();

  /**
   * Returns the name of the file.
   *
   * @return The name of the file
   */
  String filename();
}
