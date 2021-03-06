package edu.wisc.cs.sdn.apps.sps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.openflow.protocol.*;
import org.openflow.protocol.action.*;
import org.openflow.protocol.instruction.*;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.packet.*;

import java.util.*;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    // private byte table;
    public static byte table; // cannot compile LoadBalancer using SPS without access to this ID
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

    // simple container to store single-source Dijkstra's results, based on Wikipedia pseudocode
    private class DijkstraResults {
        // data members
        private HashMap<IOFSwitch, Integer> dist;
        private HashMap<IOFSwitch, IOFSwitch> prev;

        // constructor
        public DijkstraResults(HashMap<IOFSwitch, Integer> d, HashMap<IOFSwitch, IOFSwitch> p) {
            this.dist = d;
            this.prev = p;
        }

        public HashMap<IOFSwitch, Integer> getDist() {
            return this.dist;
        }

        public HashMap<IOFSwitch, IOFSwitch> getPrev() {
            return this.prev;
        }
    }

    // map of switches to DijkstraResults (set by as_dijkstra function)
    public HashMap<IOFSwitch, DijkstraResults> pathData;

    // in fact, we only need the previous-hop data for rules installation:
    public HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> allPrev;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        /*********************************************************************/

        // initialize our added data structures for Dijkstra's shortest paths
        this.pathData = new HashMap<IOFSwitch, DijkstraResults>();
        this.allPrev = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		/*********************************************************************/
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    // helper function to get neighbors of a switch
    public Set<IOFSwitch> getNeighbors(IOFSwitch source) {
        Set<IOFSwitch> Neighbors = new HashSet<IOFSwitch>();
        Collection<Link> Edges = this.getLinks();
        Map<Long, IOFSwitch> Nodes = this.getSwitches();
        for (Link e : Edges) {
            IOFSwitch s = Nodes.get(e.getSrc());
            IOFSwitch d = Nodes.get(e.getDst());
            if (s == source) {
                Neighbors.add(d);
            }
        }
        return Neighbors;
    }

    // helper function to facilitate Wikipedia pseudocode implementation of Dijkstra's
    public IOFSwitch getMinDistElement(Set<IOFSwitch> Q, HashMap<IOFSwitch, Integer> dist) {
        Integer minDistSeen = Integer.MAX_VALUE;
        IOFSwitch minSwitch = null;
        if (Q.isEmpty() == false) {
            for (IOFSwitch s : Q) {
                if (dist.containsKey(s)) {
                    Integer thisDist = dist.get(s);
                    if (thisDist < minDistSeen) {
                        minDistSeen = thisDist;
                        minSwitch = s;
                    }
                }
            }
        }
        return minSwitch;
    }

    // Dijkstra's implementation, following pseudocode on Wikipedia: https://en.wikipedia.org/wiki/Dijkstra's_algorithm
    public DijkstraResults ss_dijkstra(IOFSwitch source) {
        // create vertex set Q; for us, this will be a set of switches
        Set<IOFSwitch> Q = new HashSet<IOFSwitch>();
        
        // need to track the predecessor of every node in the shortest path graph and distance to it
        HashMap<IOFSwitch, Integer> dist = new HashMap<IOFSwitch, Integer>();
        HashMap<IOFSwitch, IOFSwitch> prev = new HashMap<IOFSwitch, IOFSwitch>();

        // initialize our hash maps and Q -- use (Integer.MAX_VALUE - 1) as "INFINITY" and null as "UNDEFINED"
        Collection<IOFSwitch> Graph = this.getSwitches().values(); // the actual switches
        for (IOFSwitch v : Graph) {
            dist.put(v, Integer.MAX_VALUE - 1); // make this 1 less than MAX_VALUE so we can compare in getMinDistElement
            prev.put(v, null);
            Q.add(v);
        }
        // and set distance from source to self to be 0
        dist.put(source, 0);

        // initialize neighbor distances to 1 (no edge weights)
        Set<IOFSwitch> Neighbors = this.getNeighbors(source);
        for (IOFSwitch n : Neighbors) {
            dist.put(n, 1);
            prev.put(n, source);
        }
        
        // main loop
        while (Q.isEmpty() == false) {
            // get vertex in Q with min dist
            IOFSwitch u = getMinDistElement(Q, dist);

            // remove u from Q
            Q.remove(u);

            // loop over neighbors of u that are still in Q:
            Set<IOFSwitch> uNeighbors = this.getNeighbors(u);
            for (IOFSwitch v : uNeighbors) {
                if (Q.contains(v)) {
                    // consider all link distances to be 1 for now
                    Integer alt = dist.get(u) + 1;
                    if (alt < dist.get(v)) {
                        dist.put(v, alt);
                        prev.put(v, u);
                    }
                }
            }
        }
        
        // Wikipedia says to return dist and prev here; need to consider best data structure
        // pack into simple container with getters to fetch as needed
        DijkstraResults res = new DijkstraResults(dist, prev);
        return res;
    }


    // if ss_dijkstra works, do an as_dijkstra just looping over every possible source node
    public void as_dijkstra() {
        // get set of all possible source nodes (switches)
        Collection<IOFSwitch> allSources = this.getSwitches().values();

        // for each source, store Dijkstra results from single-source run in a HashMap to set as pathData
        HashMap<IOFSwitch, DijkstraResults> res = new HashMap<IOFSwitch, DijkstraResults>();
        // also capture only the prev data as a shortcut, since we don't need the weights for rules installation:
        HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>> prevData = new HashMap<IOFSwitch, HashMap<IOFSwitch, IOFSwitch>>();
        for (IOFSwitch s : allSources) {
            DijkstraResults dr = ss_dijkstra(s);
            HashMap<IOFSwitch, IOFSwitch> prevPath = dr.getPrev();
            res.put(s, dr);
            prevData.put(s, prevPath);
        }
        this.pathData = res;
        this.allPrev = prevData;
    }


    // need some way to go from map of switch -> DijkstraResults to "rules"
    // and need to insert said "rules" into the various switches somehow
    // use same "single" / "all" pattern here that we used for Dijkstra's
    public void installRulesForSingleHost(Host h) {
        // make sure the host is on the network
        if (h.isAttachedToSwitch() == false) {
            // System.out.println("Host " + h + " is not on the network - cannot install rules");
            return;
        }

        // once we are sure the host is on the network, get metadata about its connection
        IOFSwitch hSwitch = h.getSwitch();
        Integer hPort = h.getPort();

        // create a new OFMatch object for our rule we want to install
        OFMatch match = new OFMatch();
        // per Wisconsin instructions, MUST set Ethernet Type before setting destination:
        // http://pages.cs.wisc.edu/~akella/CS640/F19/assignment4/
        match.setField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
        match.setField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(h.getMACAddress()));

        // need to traverse all switches to set rules about reaching host h
        Collection<IOFSwitch> Graph = this.getSwitches().values();
        for (IOFSwitch s : Graph) {
            // create an OFActionOutput object which we need to set the port # on, per instructions
            OFActionOutput action = new OFActionOutput();

            // set the port in the action, as instructed
            if (s.getId() == hSwitch.getId()) {
                // if this is our host's switch, just use the port it is already attached to
                action.setPort(hPort);
            } else {
                // use our pathData object to find the next hop switch on the path to our host's switch
                // DijkstraResults dr = pathData.get(hSwitch);
                // HashMap<IOFSwitch, IOFSwitch> hops = dr.getPrev();
                // IOFSwitch nextHop = hops.get(s);

                // can just directly use our new allPrev object as we only need prev data:
                IOFSwitch nextHop = this.allPrev.get(hSwitch).get(s);

                // get the link connecting current switch to nextHop
                Collection<Link> allLinks = this.getLinks();
                for(Link l : allLinks) {
                    if((s.getId() == l.getSrc()) && (nextHop.getId() == l.getDst())) {
                        action.setPort(l.getSrcPort());
                    }
                }
            }

            // then create the OFInstructionApplyActions object containing this action
            List<OFAction> actionsToApply = new ArrayList<OFAction>();
            actionsToApply.add(action);
            OFInstructionApplyActions rules = new OFInstructionApplyActions(actionsToApply);

            // also need to subsequently install these rules in the switch - requires List<OFInstruction>
            List<OFInstruction> rulesToAdd = new ArrayList<OFInstruction>();
            rulesToAdd.add(rules);
            // per instructions, use default priority and no timeouts
            SwitchCommands.installRule(s, this.table, SwitchCommands.DEFAULT_PRIORITY, match, rulesToAdd,
                                        SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT);
        }
    }

    // similarly extend with a wrapper that will call the rule installer for all hosts
    // this function should be invoked whenever things get added to the network / network changes
    public void installRulesForAllHosts() {
        // first, call all-paths Dijkstra to make sure we are basing rules on latest paths
        // System.out.println("\nInstalling rules for all hosts - refreshing path data\n");
        as_dijkstra();

        // then call the per-host rule installation for each host
        Collection<Host> allHosts = this.getHosts();
        for (Host h : allHosts) {
            installRulesForSingleHost(h);
        }
    }

    // assuming the above works, then need a way to reset all the rules if things get deleted
    // just call this function before any invocation of installRulesForAllHosts to be safe
    public void deleteRulesForSingleHost(Host h) {
        // evidently the way you have to do this is with the same OFMatch object used to set the rule
        // (per SwitchCommands.java) -- using code from installRulesForSingleHost above:
        OFMatch match = new OFMatch();
        match.setField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
        match.setField(OFOXMFieldType.ETH_DST, Ethernet.toByteArray(h.getMACAddress()));

        // need to traverse all switches to set rules about reaching host h
        Collection<IOFSwitch> Graph = this.getSwitches().values();
        for (IOFSwitch s : Graph) {
            SwitchCommands.removeRules(s, this.table, match);
        }
    }

    // extend with wrapper to delete rules for all hosts
    // use to reset network rules when things change (follow w/ call to install new rules)
    public void deleteRulesForAllHosts() {
        Collection<Host> allHosts = this.getHosts();
        for (Host h : allHosts) {
            deleteRulesForSingleHost(h);
        }
    }


    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			/*****************************************************************/

            as_dijkstra(); // need to call separately here; not wrapped
            installRulesForSingleHost(host);
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		/*********************************************************************/

        deleteRulesForSingleHost(host);
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		/*********************************************************************/

        deleteRulesForSingleHost(host);
        as_dijkstra();
        installRulesForSingleHost(host);
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/
        
        // just refresh everything when switches change
        deleteRulesForAllHosts();
        installRulesForAllHosts();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/

        // just refresh everything when switches change
        deleteRulesForAllHosts();
        installRulesForAllHosts();
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/

        // just refresh everything when links change
        deleteRulesForAllHosts();
        installRulesForAllHosts();
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}
