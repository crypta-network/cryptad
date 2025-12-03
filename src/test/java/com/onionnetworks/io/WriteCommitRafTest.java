package com.onionnetworks.io;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.onionnetworks.util.Range;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class WriteCommitRafTest {

  @Mock RAF delegate;

  private WriteCommitRaf writeCommitRaf;

  @BeforeEach
  void setUp() {
    writeCommitRaf = spy(new WriteCommitRaf(delegate));
  }

  @Test
  void seekAndWrite_whenBytesWritten_commitsRange() throws Exception {
    byte[] data = new byte[] {1, 2, 3};

    writeCommitRaf.seekAndWrite(5, data, 0, data.length);

    InOrder order = inOrder(delegate, writeCommitRaf);
    order.verify(delegate).seekAndWrite(5L, data, 0, data.length);
    order.verify(writeCommitRaf).commit(new Range(5, 7));
  }

  @Test
  void seekAndWrite_whenZeroLength_doesNotCommitRange() throws Exception {
    byte[] data = new byte[0];

    writeCommitRaf.seekAndWrite(2, data, 0, 0);

    verify(delegate).seekAndWrite(2L, data, 0, 0);
    verify(writeCommitRaf, never()).commit(any(Range.class));
  }

  @Test
  void setReadOnly_whenFileHasData_commitsFullLength() throws Exception {
    when(delegate.length()).thenReturn(8L);

    writeCommitRaf.setReadOnly();

    InOrder order = inOrder(delegate, writeCommitRaf);
    order.verify(delegate).setReadOnly();
    order.verify(delegate).length();
    order.verify(writeCommitRaf).commit(new Range(0, 7));
  }

  @Test
  void setReadOnly_whenFileIsEmpty_skipsCommit() throws Exception {
    when(delegate.length()).thenReturn(0L);

    writeCommitRaf.setReadOnly();

    verify(delegate).setReadOnly();
    verify(delegate).length();
    verify(writeCommitRaf, never()).commit(any(Range.class));
  }
}
