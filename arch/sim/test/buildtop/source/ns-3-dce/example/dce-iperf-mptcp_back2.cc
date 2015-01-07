#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <map>
#include <string.h>
#include <sstream>

#include "ns3/network-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/dce-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/constant-position-mobility-model.h"

using namespace ns3;
using namespace std;

void setPos(Ptr<Node> n, int x, int y, int z) {
	Ptr < ConstantPositionMobilityModel > loc = CreateObject<
			ConstantPositionMobilityModel>();
	n->AggregateObject(loc);
	Vector locVec2(x, y, z);
	loc->SetPosition(locVec2);
}

char* string2char(string s){
	int len = s.length();
	char* c = new char[len+1];
	memcpy(c, s.c_str(), len+1);
	return c;
}

int host_detect(char *adrs){
	const char delm[] = ".";
	char *tok;
	int host;

	tok = strtok(adrs, delm);
	int j = 0;
	while(tok != NULL){
		if(j == 2){
			host = atoi(tok);
			break;
		}
		tok = strtok(NULL, delm);
		j++;
	}
	return host;
}


void socketTraffic(uint32_t byte, double end, NodeContainer nodes){
	//uint32_t kb = 70;
	uint32_t size = byte * 1024;
	//double end = 5.0;

	ApplicationContainer apps, sinkApps;
	DceApplicationHelper process;
	std::string sock_factory = "ns3::LinuxTcpSocketFactory";

	BulkSendHelper bulk = BulkSendHelper (sock_factory, InetSocketAddress ("10.2.0.1", 50000));
	bulk.SetAttribute ("MaxBytes", UintegerValue (size));
	apps = bulk.Install (nodes.Get(1));

	apps.Start(Seconds(1.5));
	apps.Stop(Seconds(end));

	PacketSinkHelper sink = PacketSinkHelper (sock_factory, InetSocketAddress (Ipv4Address::GetAny (), 50000));
	sinkApps = sink.Install (nodes.Get(0));
	sinkApps.Start (Seconds (1.5));
	sinkApps.Stop (Seconds (end));
}

void socketTraffic2(multimap<int, string> &ip_set, uint32_t byte, double start, double end, NodeContainer nodes){
	uint32_t size = byte * 1000 - 1502;
	int tasks = ip_set.size();
	ApplicationContainer apps[tasks], sinkApps[tasks];
	//BulkSendHelper bulk;
	//PacketSinkHelper sink[tasks];
	multimap<int, string>::iterator it = ip_set.begin();
	string sock_factory = "ns3::LinuxTcpSocketFactory";
	int i = 0;
	while(it != ip_set.end()){
		//BulkSendHelper bulk[i];
		cout << "IP : " << (*it).second << endl;
		BulkSendHelper bulk = BulkSendHelper (sock_factory, InetSocketAddress (string2char((*it).second), 50000));
		bulk.SetAttribute ("MaxBytes", UintegerValue (size));
		apps[0] = bulk.Install (nodes.Get((*it).first));

		apps[0].Start(Seconds(start));
		apps[0].Stop(Seconds(end));

		PacketSinkHelper sink = PacketSinkHelper (sock_factory, InetSocketAddress (Ipv4Address::GetAny (), 50000));
		int ser = host_detect(string2char((*it).second));
		sinkApps[0] = sink.Install (nodes.Get(ser));
		sinkApps[0].Start (Seconds (start));
		sinkApps[0].Stop (Seconds (end));
		++it;
		i++;
	}

}

int main(int argc, char *argv[]) {
	uint32_t nRtrs = 1;
	CommandLine cmd;
	cmd.AddValue("nRtrs", "Number of routers. Default 2", nRtrs);
	cmd.Parse(argc, argv);

	NodeContainer nodes;
	nodes.Create(2);
	//routers.Create(nRtrs);

	DceManagerHelper dceManager;
	dceManager.SetTaskManagerAttribute("FiberManagerType", StringValue("UcontextFiberManager"));
	dceManager.SetNetworkStack("ns3::LinuxSocketFdFactory", "Library", StringValue("liblinux.so"));
	LinuxStackHelper stack;
	stack.Install(nodes);
	//stack.Install(routers);

	dceManager.Install(nodes);
	//dceManager.Install(routers);

	PointToPointHelper pointToPoint, pointToPoint2;
	NetDeviceContainer devices[10];
	Ipv4AddressHelper address1, address2, address3, address4;
	std::ostringstream cmd_oss;
	address1.SetBase("10.1.0.0", "255.255.255.0");
	address2.SetBase("10.2.0.0", "255.255.255.0");
	address3.SetBase("10.3.0.0", "255.255.255.0");
	address4.SetBase("10.4.0.0", "255.255.255.0");
	// link
	pointToPoint.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
	pointToPoint.SetChannelAttribute("Delay", TimeValue(MicroSeconds(100)));
	//pointToPoint2.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
	//pointToPoint2.SetChannelAttribute("Delay", StringValue("10ms"));

	devices[1] = pointToPoint.Install(nodes.Get(0), nodes.Get(1));
	devices[2] = pointToPoint.Install(nodes.Get(0), nodes.Get(1));
	devices[3] = pointToPoint.Install(nodes.Get(0), nodes.Get(1));
	//devices[4] = pointToPoint2.Install(nodes.Get(0), nodes.Get(1));

	// Assign ip addresses
	Ipv4InterfaceContainer if1 = address1.Assign(devices[1]);
	//if1 = address2.Assign(devices[1]);
	//if1 = address3.Assign(devices[1]);
	//if1 = address4.Assign(devices[1]);

	Ipv4InterfaceContainer if2 = address2.Assign(devices[2]);
	Ipv4InterfaceContainer if3 = address3.Assign(devices[3]);
	//Ipv4InterfaceContainer if4 = address4.Assign(devices[4]);

	//set iproute
	cmd_oss.str("");
	cmd_oss << "route add 10.1.0.0/24 via 10.1.0.2";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(0), Seconds(0.1), cmd_oss.str().c_str());
		cmd_oss.str("");
	cmd_oss << "route add 10.2.0.0/24 via 10.2.0.2";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(0), Seconds(0.1), cmd_oss.str().c_str());
	cmd_oss.str("");
	cmd_oss << "route add 10.3.0.0/24 via 10.3.0.2";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(0), Seconds(0.1), cmd_oss.str().c_str());
	cmd_oss.str("");
	cmd_oss << "route add 10.4.0.0/24 via 10.4.0.2";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(0), Seconds(0.1), cmd_oss.str().c_str());


	cmd_oss.str("");
	cmd_oss << "route add 10.1.0.0/24 via 10.1.0.1";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(1), Seconds(0.1), cmd_oss.str().c_str());
		cmd_oss.str("");
	cmd_oss << "route add 10.2.0.0/24 via 10.2.0.1";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(1), Seconds(0.1), cmd_oss.str().c_str());

	cmd_oss.str("");
	cmd_oss << "route add 10.3.0.0/24 via 10.3.0.1";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(1), Seconds(0.1), cmd_oss.str().c_str());
	cmd_oss.str("");
	cmd_oss << "route add 10.4.0.0/24 via 10.4.0.1";
	cout << cmd_oss.str() << endl;
	LinuxStackHelper::RunIp(nodes.Get(1), Seconds(0.1), cmd_oss.str().c_str());

	// debug
	stack.SysctlSet(nodes, ".net.mptcp.mptcp_debug", "1");

	stack.SysctlSet (nodes, ".net.ipv4.tcp_rmem", "500000 500000 500000");
	stack.SysctlSet (nodes, ".net.ipv4.tcp_wmem", "500000 500000 500000");
	stack.SysctlSet (nodes, ".net.core.rmem_max", "500000");
	stack.SysctlSet (nodes, ".net.core.wmem_max", "500000");

	multimap<int, string> adrs_set;
	adrs_set.insert(map<int, string>::value_type(0, "10.1.0.2"));
	uint32_t kb = 70;
	double end = 10.0;
	string end_t = "10.0";

	//socketTraffic(kb, end, nodes);

	DceApplicationHelper dce;
	ApplicationContainer apps;

	dce.SetStackSize(1 << 20);

	// Launch iperf client on node 0
	dce.SetBinary("iperf");
	dce.ResetArguments();
	dce.ResetEnvironment();
	dce.AddArgument ("-c");
	dce.AddArgument ("10.1.0.2");
	dce.AddArgument ("-i");
	dce.AddArgument ("1");
	dce.AddArgument ("--time");
	dce.AddArgument ("4");

	apps = dce.Install(nodes.Get(0));
	apps.Start(Seconds(1));
	apps.Stop(Seconds(5));

	// Launch iperf server on node 1
	dce.SetBinary("iperf");
	dce.ResetArguments();
	dce.ResetEnvironment();
	dce.AddArgument("-s");
	dce.AddArgument ("-P");
	dce.AddArgument ("1");
	//dce.AddArgument("-u");

	apps = dce.Install(nodes.Get(1));


	//pointToPoint.EnablePcap("pcap/back2/iperf-mptcp_back2", devices[1].Get(1), false, false);
	//pointToPoint.EnablePcap("pcap/back2/iperf-mptcp_back2", devices[2].Get(1), false, false);
	pointToPoint.EnablePcapAll("pcap/back2/iperf-mptcp_back2", false);



	setPos(nodes.Get(0), 0, 20 * (nRtrs - 1) / 2, 0);
	setPos(nodes.Get(1), 100, 20 * (nRtrs - 1) / 2, 0);

	Simulator::Stop(Seconds(2.0));
	AnimationInterface anim("./xml/mptcp_back2.xml");
	Simulator::Run();
	Simulator::Destroy();

	return 0;
}
