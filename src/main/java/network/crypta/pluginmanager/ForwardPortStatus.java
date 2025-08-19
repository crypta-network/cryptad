package network.crypta.pluginmanager;

/**
 * @param externalPort Some plugins may need to change the external port. They can return it to the node here.
 */
public record ForwardPortStatus(int status, String reasonString, int externalPort) {

    /**
     * The port forward definitely succeeded.
     */
    public static final int DEFINITE_SUCCESS = 3;

    /**
     * The port forward probably succeeded. I.e. it succeeded unless there was for example hostile
     * action on the part of the router.
     */
    public static final int PROBABLE_SUCCESS = 2;

    /**
     * The port forward may have succeeded. Or it may not have. We should definitely try to check out
     * of band. See UP&P: Many routers say they've forwarded the port when they haven't.
     */
    public static final int MAYBE_SUCCESS = 1;

    /**
     * The port forward is in progress
     */
    public static final int IN_PROGRESS = 0;

    /**
     * The port forward probably failed
     */
    public static final int PROBABLE_FAILURE = -1;

    /**
     * The port forward definitely failed.
     */
    public static final int DEFINITE_FAILURE = -2;

}
