package network.crypta.clients.http.updateableelements;

import java.util.Timer;
import java.util.TimerTask;

import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;

/** A pushed element that counts up every second. Only for testing purposes. */
public class TesterElement extends BaseUpdateableElement {

	private int		status	= 0;

	private final int		maxStatus;

	ToadletContext	ctx;

	Timer			t;

	final String	id;

	public TesterElement(ToadletContext ctx, String id, int max) {
		super("div","style","float:left;", ctx);
		this.id = id;
		this.ctx = ctx;
		this.maxStatus = max;
		init(true);
		t = new Timer(true);
		t.scheduleAtFixedRate(new TimerTask() {

			@Override
			public void run() {
				update();
			}
		}, 0, 1000);
	}

	public void update() {
		status++;
		if (status >= maxStatus) {
			t.cancel();
		}
		((SimpleToadletServer) ctx.getContainer()).getPushDataManager().updateElement(getUpdaterId(ctx.getUniqueId()));
	}

	@Override
	public void dispose() {
		t.cancel();
	}

	@Override
	public String getUpdaterId(String requestId) {
		return getId(requestId,id);
	}
	
	public static String getId(String requestId,String id){
		return Base64.encodeStandardUTF8(("test:" + requestId + "id:" + id+"gndfjkghghdfukggherugbdfkutg54ibngjkdfgyisdhiterbyjhuyfghdightw7i4tfgsdgo;dfnghsdbfuiyfgfoinfsdbufvwte4785tu4kgjdfnzukfbyfhe48e54gjfdjgbdruserigbfdnvbxdio;fherigtuseofjuodsvbyfhsd8ofghfio;"));
	}

	@Override
	public String getUpdaterType() {
		return UpdaterConstants.REPLACER_UPDATER;
	}

	@Override
	public void updateState(boolean initial) {
		children.clear();
		addChild(new HTMLNode("img", "src","/imagecreator/?text="+status+"&width="+Math.min(status+30,300)+"&height="+Math.min(status+30,300)));
	}

}
