package network.crypta.node;

/** Used to associate a port with a node database handle */
// WARNING: THIS CLASS IS STORED IN DB4O -- THINK TWICE BEFORE ADD/REMOVE/RENAME FIELDS
class HandlePortTuple {
  long handle;
  int portNumber;
}
