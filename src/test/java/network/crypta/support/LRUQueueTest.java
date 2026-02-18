package network.crypta.support;

import java.util.Iterator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test case for {@link LRUQueue} class.
 *
 * @author Alberto Bacchelli &lt;sback@freenetproject.org&gt;
 */
@SuppressWarnings("java:S100") // test naming uses method_whenCondition_expectOutcome
class LRUQueueTest {

  private static final int SAMPLE_ELEMS_NUMBER = 100;

  /**
   * Creates an array of objects with a specified size
   *
   * @param size the array size
   * @return the objects array
   */
  private Object[] createSampleObjects(int size) {
    Object[] sampleObjects = new Object[size];
    for (int i = 0; i < sampleObjects.length; i++) sampleObjects[i] = new Object();
    return sampleObjects;
  }

  /**
   * Creates a LRUQueue filled with the specified objects number
   *
   * @param size queue size
   * @return the created LRUQueue
   */
  private LRUQueue<Object> createSampleQueue(int size) {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(size);
    for (Object sampleObject : sampleObjects) methodLRUQueue.push(sampleObject);
    return methodLRUQueue;
  }

  /**
   * Verifies if an element is present in an array
   *
   * @param anArray the array to search into
   * @param aElementToSearch the object that must be found
   * @return true if there is at least one reference to the object
   */
  private boolean isPresent(Object[] anArray, Object aElementToSearch) {
    for (Object o : anArray) if (o.equals(aElementToSearch)) return true;
    return false;
  }

  /**
   * Verifies if the order of the last two elements in the queue is correct
   *
   * @param aLRUQueue the LRUQueue to check
   * @param nextToLast the next-to-last element expected
   * @param last the last element expected
   * @return true if the order is correct
   */
  private boolean verifyLastElemsOrder(LRUQueue<Object> aLRUQueue, Object nextToLast, Object last) {
    boolean retVal = true;
    int size = aLRUQueue.size();
    Iterator<Object> methodEnum = aLRUQueue.elements();
    int counter = 0;
    while (methodEnum.hasNext()) {
      // next-to-last object
      if (counter == size - 2) retVal &= methodEnum.next().equals(nextToLast);
      // last object
      else if (counter == size - 1) retVal &= methodEnum.next().equals(last);
      else methodEnum.next();
      counter++;
    }
    return retVal;
  }

  /**
   * Tests {@link LRUQueue#push(Object)} method providing a null object as argument (after setting
   * up a sample queue) and verifying if the correct exception is raised
   */
  @Test
  void push_whenNull_expectNullPointerException() {
    // Arrange
    LRUQueue<Object> q = this.createSampleQueue(SAMPLE_ELEMS_NUMBER);
    // Act + Assert
    NullPointerException ex1 = assertThrows(NullPointerException.class, () -> q.push(null));
    assertNotNull(ex1);
    NullPointerException ex2 = assertThrows(NullPointerException.class, () -> q.pushLeast(null));
    assertNotNull(ex2);
  }

  /**
   * Tests {@link LRUQueue#push(Object)} method and verifies the behaviour when pushing the same
   * object more than one time.
   */
  @Test
  void push_whenSameObjectTwice_movesToMostRecentWithoutDuplication() {
    LRUQueue<Object> methodLRUQueue = this.createSampleQueue(SAMPLE_ELEMS_NUMBER);
    Object[] sampleObj = {new Object(), new Object()};

    methodLRUQueue.push(sampleObj[0]);
    methodLRUQueue.push(sampleObj[1]);

    // check size
    assertEquals(SAMPLE_ELEMS_NUMBER + 2, methodLRUQueue.size());
    // check order
    assertTrue(verifyLastElemsOrder(methodLRUQueue, sampleObj[0], sampleObj[1]));

    methodLRUQueue.push(sampleObj[0]);
    // check size
    assertEquals(SAMPLE_ELEMS_NUMBER + 2, methodLRUQueue.size());
    // check order
    assertTrue(verifyLastElemsOrder(methodLRUQueue, sampleObj[1], sampleObj[0]));
  }

  /** Tests {@link LRUQueue#pushLeast(Object)} method */
  @Test
  void pushLeast_whenCalled_placesAtLeastRecent_andMovesExistingToTail() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObj = {new Object(), new Object()};

    methodLRUQueue.push(sampleObj[0]);
    methodLRUQueue.pushLeast(sampleObj[1]);

    assertEquals(2, methodLRUQueue.size());
    assertTrue(verifyLastElemsOrder(methodLRUQueue, sampleObj[1], sampleObj[0]));

    // --> Same element
    methodLRUQueue.pushLeast(sampleObj[0]);

    assertEquals(2, methodLRUQueue.size());
    assertTrue(verifyLastElemsOrder(methodLRUQueue, sampleObj[0], sampleObj[1]));
  }

  /**
   * Tests{@link LRUQueue#pop()} method pushing and popping objects and verifying if they are
   * correctly (in a FIFO manner) fetched and deleted
   */
  @Test
  void pop_whenFilled_returnsLeastRecentThenNull() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);
    // pushing objects
    for (Object object : sampleObjects) methodLRUQueue.push(object);
    // getting objects
    for (Object sampleObject : sampleObjects) assertEquals(sampleObject, methodLRUQueue.pop());
    // the queue must be empty
    assertNull(methodLRUQueue.pop());
  }

  /**
   * Tests {@link LRUQueue#size()} method checking size when empty, when putting each object and
   * when popping each object.
   */
  @Test
  void size_whenPushingAndPopping_tracksCount() {
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    assertEquals(0, methodLRUQueue.size());
    // pushing objects
    for (int i = 0; i < sampleObjects.length; i++) {
      methodLRUQueue.push(sampleObjects[i]);
      assertEquals(i + 1, methodLRUQueue.size());
    }
    // getting all objects
    for (int i = sampleObjects.length - 1; i >= 0; i--) {
      methodLRUQueue.pop();
      assertEquals(i, methodLRUQueue.size());
    }
    assertEquals(0, methodLRUQueue.size());
  }

  /**
   * Tests {@link LRUQueue#remove(Object)} method verifies if all objects are correctly removed
   * checking the method return value, if the object is still contained and the queue size.
   */
  @Test
  void remove_whenPresent_removesAndReturnsTrue() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);
    for (Object sampleObject : sampleObjects) methodLRUQueue.push(sampleObject);
    // removing all objects in the opposite way used by pop() method
    for (int i = sampleObjects.length - 1; i >= 0; i--) {
      assertTrue(methodLRUQueue.remove(sampleObjects[i]));
      assertFalse(methodLRUQueue.contains(sampleObjects[i]));
      assertEquals(i, methodLRUQueue.size());
    }
  }

  /**
   * Tests{@link LRUQueue#remove(Object)} providing a null argument and trying to remove it after
   * setting up a sample queue.
   */
  @Test
  void remove_whenNull_expectNullPointerException() {
    LRUQueue<Object> q = createSampleQueue(SAMPLE_ELEMS_NUMBER);
    NullPointerException ex = assertThrows(NullPointerException.class, () -> q.remove(null));
    assertNotNull(ex);
  }

  /**
   * Tests {@link LRUQueue#remove(Object)} method trying to remove a not present object after
   * setting up a sample queue.
   */
  @Test
  void remove_whenNotPresent_returnsFalse() {
    LRUQueue<Object> methodLRUQueue = createSampleQueue(SAMPLE_ELEMS_NUMBER);
    assertFalse(methodLRUQueue.remove(new Object()));
  }

  /**
   * Tests {@link LRUQueue#contains(Object)} method trying to find a not present object after
   * setting up a sample queue. Then it search a present object.
   */
  @Test
  void contains_whenPresentAndNotPresent_behavesAsExpected() {
    LRUQueue<Object> methodLRUQueue = createSampleQueue(SAMPLE_ELEMS_NUMBER);
    assertFalse(methodLRUQueue.contains(new Object()));
    Object methodSampleObj = new Object();
    methodLRUQueue.push(methodSampleObj);
    assertTrue(methodLRUQueue.contains(methodSampleObj));
  }

  /** Tests {@link LRUQueue#elements()} method verifying if the iterator provided is correct */
  @Test
  void elements_whenFilled_yieldsLeastToMostRecentOrder() {
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    // pushing objects
    for (Object sampleObject : sampleObjects) methodLRUQueue.push(sampleObject);
    Iterator<Object> methodEnumeration = methodLRUQueue.elements();
    int j = 0;
    while (methodEnumeration.hasNext()) {
      assertEquals(sampleObjects[j], methodEnumeration.next());
      j++;
    }
  }

  /**
   * Tests {@link LRUQueue#toArray()} method verifying if the array generated has the same object
   * that are put into the created LRUQueue
   */
  @Test
  void toArray_whenFilled_containsAllElementsInUnspecifiedOrder() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);

    // pushing objects
    for (Object object : sampleObjects) methodLRUQueue.push(object);

    Object[] resultingArray = methodLRUQueue.toArray();

    assertEquals(sampleObjects.length, resultingArray.length);
    for (Object sampleObject : sampleObjects) assertTrue(isPresent(resultingArray, sampleObject));
  }

  /** Tests {@link LRUQueue#toArray(Object[])} method */
  @Test
  void toArray_withProvidedArrayExactSize_fillsArray() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);

    // pushing objects
    for (Object object : sampleObjects) methodLRUQueue.push(object);

    Object[] resultingArray = new Object[sampleObjects.length];
    methodLRUQueue.toArray(resultingArray);

    assertEquals(sampleObjects.length, resultingArray.length);
    for (Object sampleObject : sampleObjects) assertTrue(isPresent(resultingArray, sampleObject));
  }

  /** Tests {@link LRUQueue#toArrayOrdered()} method */
  @Test
  void toArrayOrdered_whenFilled_returnsLeastToMostRecent() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);

    // pushing objects
    for (Object sampleObject : sampleObjects) methodLRUQueue.push(sampleObject);

    Object[] resultingArray = methodLRUQueue.toArrayOrdered();

    assertEquals(sampleObjects.length, resultingArray.length);
    for (int i = 0; i < sampleObjects.length; i++)
      assertEquals(sampleObjects[i], resultingArray[i]);
  }

  /** Tests <code>toArrayOrdered(Object[])</code> method */
  @Test
  void toArrayOrdered_withProvidedArrayExactSize_fillsInOrder() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    Object[] sampleObjects = createSampleObjects(SAMPLE_ELEMS_NUMBER);

    // pushing objects
    for (Object sampleObject : sampleObjects) methodLRUQueue.push(sampleObject);

    Object[] resultingArray = new Object[sampleObjects.length];
    methodLRUQueue.toArrayOrdered(resultingArray);

    assertEquals(resultingArray.length, sampleObjects.length);
    for (int i = 0; i < sampleObjects.length; i++)
      assertEquals(sampleObjects[i], resultingArray[i]);
  }

  /** Tests toArray() method when the queue is empty */
  @Test
  void toArray_whenEmpty_returnsEmptyArray() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    assertEquals(0, methodLRUQueue.toArray().length);
  }

  /** Tests isEmpty() method trying it with an empty queue and then with a sample queue. */
  @Test
  void isEmpty_whenEmptyFilledEmptied_behavesAsExpected() {
    LRUQueue<Object> methodLRUQueue = new LRUQueue<>();
    assertTrue(methodLRUQueue.isEmpty());
    methodLRUQueue = createSampleQueue(SAMPLE_ELEMS_NUMBER);
    assertFalse(methodLRUQueue.isEmpty());
    // emptying the queue...
    for (int i = 0; i < SAMPLE_ELEMS_NUMBER; i++) methodLRUQueue.pop();
    assertTrue(methodLRUQueue.isEmpty());
  }

  // === Additional edge-case and API coverage tests ===

  @Test
  void contains_whenNull_expectFalse() {
    // Arrange
    LRUQueue<Object> q = new LRUQueue<>();
    // Act + Assert
    assertFalse(q.contains(null));
    q.push("x");
    assertFalse(q.contains(null));
  }

  @Test
  void clear_whenNotEmpty_expectEmptyAndSizeZero() {
    // Arrange
    LRUQueue<Object> q = createSampleQueue(3);
    assertFalse(q.isEmpty());
    assertEquals(3, q.size());
    // Act
    q.clear();
    // Assert
    assertTrue(q.isEmpty());
    assertEquals(0, q.size());
    assertNull(q.pop());
  }

  @Test
  void get_whenEqualKeyDifferentInstance_returnsStoredReference() {
    // Arrange
    LRUQueue<String> q = new LRUQueue<>();
    String stored = "key1";
    q.push(stored);
    // Act
    String result = q.get("key1");
    // Assert
    assertNotNull(result);
    assertSame(stored, result, "Expected the same reference stored in the queue");
  }

  @Test
  void toArrayOrdered_whenArrayTooSmall_allocatesNewAndPreservesOrder() {
    // Arrange
    LRUQueue<String> q = new LRUQueue<>();
    q.push("c");
    q.push("b");
    q.push("a"); // LRU order: c, b, a
    String[] small = new String[0];
    // Act
    String[] out = q.toArrayOrdered(small);
    // Assert
    assertEquals(3, out.length);
    assertArrayEquals(new String[] {"c", "b", "a"}, out);
  }

  @Test
  void toArrayOrdered_whenArrayLargerThanSize_throwsIllegalStateException() {
    // Arrange
    LRUQueue<String> q = new LRUQueue<>();
    q.push("y");
    q.push("x"); // size = 2
    String[] tooLarge = new String[3];
    // Act + Assert
    assertThrows(IllegalStateException.class, () -> q.toArrayOrdered(tooLarge));
  }

  @Test
  void toArrayOrdered_whenWrongComponentType_throwsArrayStoreException() {
    // Arrange
    LRUQueue<String> q = new LRUQueue<>();
    q.push("b");
    q.push("a");
    Integer[] wrongType = new Integer[2];
    // Act + Assert
    assertThrows(ArrayStoreException.class, () -> q.toArrayOrdered(wrongType));
  }

  @Test
  void elements_whenEmpty_hasNoElements() {
    // Arrange
    LRUQueue<Object> q = new LRUQueue<>();
    Iterator<Object> e = q.elements();
    // Assert
    assertFalse(e.hasNext());
  }
}
