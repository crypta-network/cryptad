package network.crypta.node.stats;

/**
 * This class represents one instance of data store. Instance is described by two properties: key
 * type and store type.
 *
 * <p>User: nikotyan Date: Apr 16, 2010
 */
public record DataStoreInstanceType(DataStoreKeyType key, DataStoreType store) {

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DataStoreInstanceType that = (DataStoreInstanceType) o;

        if (key != that.key) return false;
        return store == that.store;
    }

    @Override
    public String toString() {
        return "DataStoreInstanceType{" + "store=" + store + ", key=" + key + '}';
    }
}
