package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.openflow.protocol.*;
import org.openflow.protocol.action.*;
import org.openflow.protocol.instruction.*;

import edu.wisc.cs.sdn.apps.l3routing.IL3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;

import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import edu.wisc.cs.sdn.apps.sps.ShortestPathSwitching;
import edu.wisc.cs.sdn.apps.sps.InterfaceShortestPathSwitching;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

import java.util.*;
import java.nio.ByteBuffer; // needed to extract addresses from packets

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application - per instructions, not used in this assignment
    // private IL3Routing l3RoutingApp;

    // Interface to ShortestPathSwitching application
    private InterfaceShortestPathSwitching l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    // special priority values to give certain rules higher priority than others
    private static final short PRIORITY_LOW  = 1;
    private static final short PRIORITY_MED  = 2;
    private static final short PRIORITY_HIGH = 3;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(InterfaceShortestPathSwitching.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        /*********************************************************************/
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
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		/*********************************************************************/
	}

    // helper function to install rules at a switch for handling ARP requests
    public void installRules_ARP(IOFSwitch s) {
        // need to iterate over our load balancers to check their virtual IPs
        Collection<LoadBalancerInstance> lbs = instances.values();
        for (LoadBalancerInstance lb : lbs) {
            // follow the general pattern for creating rules used in ShortestPathSwitching
            // match portion
            OFMatch match = new OFMatch();
            match.setField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_ARP);
            match.setField(OFOXMFieldType.ARP_TPA, lb.getVirtualIP());

            // action portion
            OFActionOutput action = new OFActionOutput();
            action.setPort(OFPort.OFPP_CONTROLLER); // send to controller
            List<OFAction> actionsToApply = new ArrayList<OFAction>();
            actionsToApply.add(action);

            // rules
            OFInstructionApplyActions rules = new OFInstructionApplyActions(actionsToApply);
            List<OFInstruction> rulesToAdd = new ArrayList<OFInstruction>();
            rulesToAdd.add(rules);

            // assume no timeout for these as not specified
            SwitchCommands.installRule(s, this.table, this.PRIORITY_MED, match, rulesToAdd,
                                       SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT);
        }
    }

    // helper function to install rules at a switch for handling TCP connection to virtual IPs
    public void installRules_VIP(IOFSwitch s) {
        // use same pattern as above
        Collection<LoadBalancerInstance> lbs = instances.values();
        for (LoadBalancerInstance lb : lbs) {
            // match portion
            OFMatch match = new OFMatch();
            match.setField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
            match.setField(OFOXMFieldType.IPV4_DST, lb.getVirtualIP());

            // action portion
            OFActionOutput action = new OFActionOutput();
            action.setPort(OFPort.OFPP_CONTROLLER); // send to controller
            List<OFAction> actionsToApply = new ArrayList<OFAction>();
            actionsToApply.add(action);

            // rules
            OFInstructionApplyActions rules = new OFInstructionApplyActions(actionsToApply);
            List<OFInstruction> rulesToAdd = new ArrayList<OFInstruction>();
            rulesToAdd.add(rules);

            // assume no timeout for these as not specified
            SwitchCommands.installRule(s, this.table, this.PRIORITY_MED, match, rulesToAdd,
                                       SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT);
        }
    }

    // helper function to install rules at a switch for all other packets
    public void installRules_Others(IOFSwitch s) {
        // match portion - OFMatch will match everything, so this will be "all else" if we set priority lower
        // see notes about default constructor:
        // http://pages.cs.wisc.edu/~akella/CS640/F19/assign3/floodlight-plus-doc/org/openflow/protocol/OFMatch.html
        OFMatch match = new OFMatch();

        // per instructions, "all others" packets should be sent to ShortestPathSwitching class table data member
        OFInstructionGotoTable igt = new OFInstructionGotoTable();
        igt.setTableId(ShortestPathSwitching.table);
        List<OFInstruction> rulesToAdd = new ArrayList<OFInstruction>();
        rulesToAdd.add(igt);

        // set lower priority than prior rule sets as this is a catch-all -- don't want to override other matches
        SwitchCommands.installRule(s, this.table, this.PRIORITY_LOW, match, rulesToAdd,
                                   SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT);

    }

    // helper function to handle a received ARP packet
    public void handleARP(ARP arpPkt, int port, IOFSwitch s, byte[] em) {
        // only want to send a reply if the destination is a virtual IP
        // ARP packet address is just an array of bytes -- need to convert
        // see: https://stackoverflow.com/questions/7619058/convert-a-byte-array-to-integer-in-java-and-vice-versa
        byte[] targetAddr = arpPkt.getTargetProtocolAddress();
        ByteBuffer wrappedTargetAddr = ByteBuffer.wrap(targetAddr);
        int vip = wrappedTargetAddr.getInt();
        // also check opcode on ARP packet
        short arpOp = arpPkt.getOpCode();

        // if the packet is not bound for a virtual IP (or is not an ARP Request specifically), just ignore it:
        if (this.instances.containsKey(vip) == false || arpOp != ARP.OP_REQUEST) {
            System.out.println("ARP packet not bound for VIP or is not a request; ignoring");
            return;
        }

        // if arpPkt WAS bound for a VIP, send an ARP reply
        ARP arpReply = new ARP();

        // use same ByteBuffer trick to get the sender's address
        byte[] senderAddr = arpPkt.getSenderProtocolAddress();
        ByteBuffer wrappedSenderAddr = ByteBuffer.wrap(senderAddr);
        int srcAddr = wrappedSenderAddr.getInt();

        // set required fields here -- evidently need HW and protocol fields, + opcode
        arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arpReply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arpReply.setSenderHardwareAddress(this.instances.get(vip).getVirtualMAC());
        arpReply.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
        arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
        arpReply.setProtocolAddressLength((byte) 4);
        arpReply.setSenderProtocolAddress(vip);
        arpReply.setTargetProtocolAddress(srcAddr);
        arpReply.setOpCode(ARP.OP_REPLY);

        // ARP packet needs to be encapsulated in an Ethernet packet
        Ethernet ethPkt = new Ethernet();

        // set fields on Ethernet packet, including ARP payload
        ethPkt.setEtherType(Ethernet.TYPE_ARP);
        ethPkt.setSourceMACAddress(this.instances.get(vip).getVirtualMAC());
        ethPkt.setDestinationMACAddress(em);
        ethPkt.setPayload(arpReply);

        // now actually send the response
        SwitchCommands.sendPacket(s, (short) port, ethPkt);
    }

    // helper function to handle a TCP packet
    // wrapping code will only call this function if the destination was a VIP
    public void handleTCP(TCP tcpPkt, IPv4 ipv4Pkt, Ethernet ethPkt, int port, IOFSwitch s,
                          int ipSrcAddr, int ipDstAddr, byte[] ethSrcMAC, byte[] ethDstMAC) {

        // if TCP SYN, select host and install connection-specific rules to rewrite addresses
        if (tcpPkt.getFlags() == TCP_FLAG_SYN) {
            // follow similar match / action pattern used for installing rules elsewhere

            // obtain new destination information from load balancer
            LoadBalancerInstance lbi = this.instances.get(ipDstAddr);
            int ipDstAddr_fwd = lbi.getNextHostIP();
            byte[] MAC_fwd = getHostMACAddress(ipDstAddr_fwd);

            // client to server rule
            OFMatch match_CS = new OFMatch();
            match_CS.setField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
            match_CS.setField(OFOXMFieldType.IPV4_SRC, ipSrcAddr);
            match_CS.setField(OFOXMFieldType.IPV4_DST, ipDstAddr);
            match_CS.setField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP);
            match_CS.setField(OFOXMFieldType.TCP_SRC, tcpPkt.getSourcePort());
            match_CS.setField(OFOXMFieldType.TCP_DST, tcpPkt.getDestinationPort());
            // not sure anything else is needed ?

            // action portion for client to server rule
            OFAction actionIP_CS = new OFActionSetField(OFOXMFieldType.IPV4_DST, ipDstAddr_fwd);
            OFAction actionMAC_CS = new OFActionSetField(OFOXMFieldType.ETH_DST, MAC_fwd);
            List<OFAction> actions_CS = new ArrayList<OFAction>();
            actions_CS.add(actionIP_CS);
            actions_CS.add(actionMAC_CS);
            OFInstruction actionRules_CS = new OFInstructionApplyActions(actions_CS);

            OFInstructionGotoTable igt_CS = new OFInstructionGotoTable();
            igt_CS.setTableId(ShortestPathSwitching.table);
            List<OFInstruction> rulesToAdd_CS = new ArrayList<OFInstruction>();
            rulesToAdd_CS.add(actionRules_CS);
            rulesToAdd_CS.add(igt_CS);

            // install the rules for client to server
            // per instructions, higher priority for these, and use 20-second idle timeout
            SwitchCommands.installRule(s, this.table, this.PRIORITY_HIGH, match_CS, rulesToAdd_CS,
                                       SwitchCommands.NO_TIMEOUT, this.IDLE_TIMEOUT);


            // server to client rule -- update addresses
            OFMatch match_SC = new OFMatch();
            match_SC.setField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
            match_SC.setField(OFOXMFieldType.IPV4_SRC, ipDstAddr_fwd);
            match_SC.setField(OFOXMFieldType.IPV4_DST, ipSrcAddr);
            match_SC.setField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP);
            match_SC.setField(OFOXMFieldType.TCP_SRC, tcpPkt.getDestinationPort());
            match_SC.setField(OFOXMFieldType.TCP_DST, tcpPkt.getSourcePort());

            // action portion for server to client rule
            OFAction actionIP_SC = new OFActionSetField(OFOXMFieldType.IPV4_SRC, ipDstAddr);
            OFAction actionMAC_SC = new OFActionSetField(OFOXMFieldType.ETH_SRC, ethDstMAC);
            List<OFAction> actions_SC = new ArrayList<OFAction>();
            actions_SC.add(actionIP_SC);
            actions_SC.add(actionMAC_SC);
            OFInstruction actionRules_SC = new OFInstructionApplyActions(actions_SC);

            OFInstructionGotoTable igt_SC = new OFInstructionGotoTable();
            igt_SC.setTableId(ShortestPathSwitching.table);
            List<OFInstruction> rulesToAdd_SC = new ArrayList<OFInstruction>();
            rulesToAdd_SC.add(actionRules_SC);
            rulesToAdd_SC.add(igt_SC);

            // install the rules for client to server
            // per instructions, higher priority for these, and use 20-second idle timeout
            SwitchCommands.installRule(s, this.table, this.PRIORITY_HIGH, match_SC, rulesToAdd_SC,
                                       SwitchCommands.NO_TIMEOUT, this.IDLE_TIMEOUT);
        } else {
            // send TCP reset per instructions - can reuse existing packets
            TCP tcpRst = tcpPkt;

            // update fields for TCP reset reply
            tcpRst.setSourcePort(tcpPkt.getDestinationPort());
            tcpRst.setDestinationPort(tcpPkt.getSourcePort());
            tcpRst.setFlags((short) 0x04); // TCP Reset flag
            tcpRst.setSequence(tcpPkt.getAcknowledge());
            tcpRst.setWindowSize((short) 0);
            tcpRst.setChecksum((short) 0);
            tcpRst.serialize();

            // TCP packet needs to go inside an IPv4 packet
            IPv4 ipv4Rst = ipv4Pkt;

            // update fields for IPv4 packet
            ipv4Rst.setSourceAddress(ipDstAddr);
            ipv4Rst.setDestinationAddress(ipSrcAddr);
            ipv4Rst.setChecksum((short) 0);
            ipv4Rst.setPayload(tcpRst);
            ipv4Rst.serialize();

            // IPv4 packet neets to go inside an Ethernet packet
            Ethernet ethRst = ethPkt;

            // update fields for Ethernet packet
            ethRst.setSourceMACAddress(ethDstMAC);
            ethRst.setDestinationMACAddress(ethSrcMAC);
            ethRst.setPayload(ipv4Rst);

            // actually send the reset
            SwitchCommands.sendPacket(s, (short) port, ethRst);
        }
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
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */
		/*********************************************************************/

        installRules_VIP(sw);
        installRules_ARP(sw);
        installRules_Others(sw);
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0,
				pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other packets                             */
		/*********************************************************************/

        // handle ARP requests
        if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
            // get metadata to pass through to helper function
            ARP arpPkt = (ARP) ethPkt.getPayload();
            int pktPort = pktIn.getInPort();
            byte[] ethMAC = ethPkt.getSourceMACAddress();

            // call helper
            handleARP(arpPkt, pktPort, sw, ethMAC);
        }

        // handle TCP packets
        if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4) {
            // make sure we are dealing with a packet sent to a virtual IP
            IPv4 ipPkt = (IPv4) ethPkt.getPayload();
            int ipDstAddr = ipPkt.getDestinationAddress();
            if ((this.instances.containsKey(ipDstAddr)) && (ipPkt.getProtocol() == IPv4.PROTOCOL_TCP)) {
                // get TCP packet out of IP packet
                TCP tcpPkt = (TCP) ipPkt.getPayload();

                // extract other metadata potentially needed by helper function
                int pktPort = pktIn.getInPort();
                int ipSrcAddr = ipPkt.getSourceAddress();
                byte[] ethSrcMAC = ethPkt.getSourceMACAddress();
                byte[] ethDstMAC = ethPkt.getDestinationMACAddress();

                // call helper
                handleTCP(tcpPkt, ipPkt, ethPkt, pktPort, sw, ipDstAddr, ipSrcAddr, ethDstMAC, ethSrcMAC);
            }
            // if not dealing with a packet bound for a virtual IP, fall through here
        }
		
        // for any other packet, do nothing

		return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

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
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
