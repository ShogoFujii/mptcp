#include <iostream>

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

int main(int argc, char *argv[]) {
	uint32_t nSize = 2;
	CommandLine cmd;
	cmd.AddValue("nSize", "FatTree Size. Default 4", nSize);
	cmd.Parse(argc, argv);
	uint32_t nCore = nSize * nSize;
	uint32_t nAggr = 2 * nSize * nSize;
	uint32_t nEdge = 2 * nSize * nSize;
	uint32_t nHost = nEdge * nSize;
	/*
	 for(uint32_t i=0;i<nCore;i++){

	 }*/
	NodeContainer core, aggr, edge, host;
	core.Create(nCore);
	aggr.Create(nAggr);
	edge.Create(nEdge);
	host.Create(nHost);

	DceManagerHelper dceManager;
	dceManager.SetTaskManagerAttribute("FiberManagerType",
			StringValue("UcontextFiberManager"));

	dceManager.SetNetworkStack("ns3::LinuxSocketFdFactory", "Library",
			StringValue("liblinux.so"));
	LinuxStackHelper stack;
	stack.Install(core);
	stack.Install(aggr);
	stack.Install(edge);
	stack.Install(host);

	dceManager.Install(core);
	dceManager.Install(aggr);
	dceManager.Install(edge);
	dceManager.Install(host);

	PointToPointHelper pointToPoint_he, pointToPoint_ea, pointToPoint_ac;
	NetDeviceContainer devices_he[nEdge], devices_he2[nEdge], devices_he3[nEdge], devices_he4[nEdge], devices_ea[nAggr], devices_ea2[nAggr], devices_ac[nAggr];
	Ipv4AddressHelper address_he, address_he2,address_he3, address_he4, address_he5, address_ea, address_ea2, address_ac;
	Ipv4InterfaceContainer if_he[nAggr], if_he2[nAggr],if_he3[nAggr], if_he4[nAggr], if_ea[nAggr], if_ea2[nAggr], if_ac[nAggr];
	std::ostringstream cmd_oss;
	address_he.SetBase("10.1.0.0", "255.255.255.0");
	address_he2.SetBase("10.2.0.0", "255.255.255.0");
	address_he3.SetBase("10.3.0.0", "255.255.255.0");
	address_he4.SetBase("10.4.0.0", "255.255.255.0");
	address_he5.SetBase("10.5.0.0", "255.255.255.0");
	address_ea.SetBase("10.32.0.0", "255.255.255.0");
	address_ea2.SetBase("10.33.0.0", "255.255.255.0");
	address_ac.SetBase("10.35.0.0", "255.255.255.0");

	pointToPoint_he.SetDeviceAttribute("DataRate", StringValue("250Mbps"));
	pointToPoint_he.SetChannelAttribute("Delay", TimeValue(MicroSeconds(25)));

	pointToPoint_ea.SetDeviceAttribute("DataRate", StringValue("500Mbps"));
	pointToPoint_ea.SetChannelAttribute("Delay", TimeValue(MicroSeconds(25)));

	pointToPoint_ac.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
	pointToPoint_ac.SetChannelAttribute("Delay", TimeValue(MicroSeconds(25)));

	cout << "nSize : " << nSize << endl;
	cout << "nCore : " << nCore << endl;
	cout << "nEdge : " << nEdge << endl;
	cout << "nAggr : " << nAggr << endl;
	cout << "nHost : " << nHost << endl;
	uint32_t i = 0, j = 0, k = 0;

	for (uint32_t i = 0; i < nEdge; i++) {
		//from host to edge
		for (uint32_t j = 0; j < nSize; j++) {
			k = i * nSize + j; //k:index for all nodes
			devices_he[i] = pointToPoint_he.Install(edge.Get(i), host.Get(k));
			devices_he2[i] = pointToPoint_he.Install(edge.Get(i), host.Get(k));
			devices_he3[i] = pointToPoint_he.Install(edge.Get(i), host.Get(k));
			devices_he4[i] = pointToPoint_he.Install(edge.Get(i), host.Get(k));
			if_he[i] = address_he.Assign(devices_he[i]);
			if_he2[i] = address_he2.Assign(devices_he2[i]);
			if_he3[i] = address_he3.Assign(devices_he3[i]);
			if_he4[i] = address_he4.Assign(devices_he4[i]);
			address_he.NewNetwork();
			address_he2.NewNetwork();
			address_he3.NewNetwork();
			address_he4.NewNetwork();
			//setup ip route
			////configure of host
			cmd_oss.str("");
			cmd_oss << "route add default via " << if_he[i].GetAddress(0, 0);
			cout <<"host" << k << "  :  " << cmd_oss.str() << endl;
			LinuxStackHelper::RunIp(host.Get(k), Seconds(0.1), cmd_oss.str().c_str());

			cmd_oss.str("");
			cmd_oss << "route add default via " << if_he2[i].GetAddress(0, 0);
			cout <<"host" << k << "  :  " << cmd_oss.str() << endl;
			LinuxStackHelper::RunIp(host.Get(k), Seconds(0.1), cmd_oss.str().c_str());

			cmd_oss.str("");
			cmd_oss << "route add default via " << if_he3[i].GetAddress(0, 0);
			cout <<"host" << k << "  :  " << cmd_oss.str() << endl;
			LinuxStackHelper::RunIp(host.Get(k), Seconds(0.1), cmd_oss.str().c_str());

			cmd_oss.str("");
			cmd_oss << "route add default via " << if_he4[i].GetAddress(0, 0);
			cout <<"host" << k << "  :  " << cmd_oss.str() << endl;
			LinuxStackHelper::RunIp(host.Get(k), Seconds(0.1), cmd_oss.str().c_str());

			////configure of edge

			cmd_oss.str("");
			cmd_oss << "route add 10.1."<< k <<".0/24 via " << if_he[i].GetAddress(0, 0);
			cout <<"edge" << i << "  :  " << cmd_oss.str() << endl;
			LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
			cmd_oss.str("");
			cmd_oss << "route add 10.2."<< k <<".0/24 via " << if_he2[i].GetAddress(0, 0);
			cout <<"edge" << i << "  :  " << cmd_oss.str() << endl ;
			LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
			cmd_oss.str("");

			cmd_oss << "route add 10.3."<< k <<".0/24 via " << if_he3[i].GetAddress(0, 0);
			cout <<"edge" << i << "  :  " << cmd_oss.str() << endl;
			LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
			cmd_oss.str("");
			cmd_oss << "route add 10.4."<< k <<".0/24 via " << if_he4[i].GetAddress(0, 0);
			cout <<"edge" << i << "  :  " << cmd_oss.str() << endl << endl;
			LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
			cmd_oss.str("");
		}

		//from edge to aggr
		if (i % 2 == 0) {
			devices_ea[i] = pointToPoint_ea.Install(aggr.Get(i), edge.Get(i));
			if_ea[i] = address_ea.Assign(devices_ea[i]);
			address_ea.NewNetwork();
			devices_ea[i+1] = pointToPoint_ea.Install(aggr.Get(i),edge.Get(i + 1));
			if_ea[i+1] = address_ea.Assign(devices_ea[i+1]);
			address_ea.NewNetwork();

			devices_ea2[i] = pointToPoint_ea.Install(aggr.Get(i), edge.Get(i));
			if_ea2[i] = address_ea2.Assign(devices_ea2[i]);
			address_ea2.NewNetwork();
			devices_ea2[i+1] = pointToPoint_ea.Install(aggr.Get(i),edge.Get(i + 1));
			if_ea2[i+1] = address_ea2.Assign(devices_ea2[i+1]);
			address_ea2.NewNetwork();
			for (uint32_t j = 0; j < nHost; j++) {
				if(i == j / nSize){
					//setup ip route
					////configure of aggr
					cmd_oss.str("");
					cmd_oss << "route add 10.1." << j << ".0/24 via " << if_ea[i].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.2." << j << ".0/24 via " << if_ea2[i].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}else{
					////configure of edge
					cmd_oss.str("");
					cmd_oss << "route add 10.1." << j << ".0/24 via " << if_ea[i].GetAddress(1, 0);
					cout <<"edge" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.2." << j << ".0/24 via " << if_ea2[i].GetAddress(1, 0);
					cout <<"edge" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}
			}
			cout << endl;
			for (uint32_t j = 0; j < nHost; j++) {
				if(i + 1 == j / nSize){
					//setup ip route
					////configure of aggr
					cmd_oss.str("");
					cmd_oss << "route add 10.1." << j << ".0/24 via " << if_ea[i+1].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.2." << j << ".0/24 via " << if_ea2[i+1].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}else{
					////configure of edge
					cmd_oss.str("");
					cmd_oss << "route add 10.1." << j << ".0/24 via " << if_ea[i+1].GetAddress(1, 0);
					cout <<"edge" << i + 1 << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i+1), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.2." << j << ".0/24 via " << if_ea2[i+1].GetAddress(1, 0);
					cout <<"edge" << i + 1 << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i+1), Seconds(0.2), cmd_oss.str().c_str());
				}
			}

			cout << endl;

		} else {
			devices_ea[i - 1] = pointToPoint_ea.Install(aggr.Get(i), edge.Get(i - 1));
			if_ea[i - 1] = address_ea.Assign(devices_ea[i - 1]);
			address_ea.NewNetwork();
			devices_ea[i] = pointToPoint_ea.Install(aggr.Get(i),edge.Get(i));
			if_ea[i] = address_ea.Assign(devices_ea[i]);
			address_ea.NewNetwork();

			devices_ea2[i - 1] = pointToPoint_ea.Install(aggr.Get(i), edge.Get(i - 1));
			if_ea2[i - 1] = address_ea2.Assign(devices_ea2[i - 1]);
			address_ea2.NewNetwork();
			devices_ea2[i] = pointToPoint_ea.Install(aggr.Get(i),edge.Get(i));
			if_ea2[i] = address_ea2.Assign(devices_ea2[i]);
			address_ea2.NewNetwork();

			for (uint32_t j = 0; j < nHost; j++) {
				if(i - 1 == j / nSize){
					//setup ip route
					////configure of aggr
					cmd_oss.str("");
					cmd_oss << "route add 10.3." << j << ".0/24 via " << if_ea[i-1].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.4." << j << ".0/24 via " << if_ea2[i-1].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}else{
					////configure of edge
					cmd_oss.str("");
					cmd_oss << "route add 10.3." << j << ".0/24 via " << if_ea[i-1].GetAddress(1, 0);
					cout <<"edge" << i - 1 << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i - 1), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.4." << j << ".0/24 via " << if_ea2[i-1].GetAddress(1, 0);
					cout <<"edge" << i - 1 << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i - 1), Seconds(0.2), cmd_oss.str().c_str());

				}
			}

			cout << endl;
			for (uint32_t j = 0; j < nHost; j++) {
				if(i == j / nSize){
					//setup ip route
					////configure of aggr
					cmd_oss.str("");
					cmd_oss << "route add 10.3." << j << ".0/24 via " << if_ea[i].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.4." << j << ".0/24 via " << if_ea2[i].GetAddress(0, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}else{
					////configure of edge
					cmd_oss.str("");
					cmd_oss << "route add 10.3." << j << ".0/24 via " << if_ea[i].GetAddress(1, 0);
					cout <<"edge" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					cmd_oss.str("");
					cmd_oss << "route add 10.4." << j << ".0/24 via " << if_ea2[i].GetAddress(1, 0);
					cout <<"edge" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(edge.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}
			}
			cout << endl;

		}
		//from aggr to core
		for (uint32_t l = 0; l < nCore; l++) {
			if((l < 2 && i % 2 == 0) || (l >= 2 && i % 2 != 0)){
				devices_ac[i] = pointToPoint_ac.Install(aggr.Get(i), core.Get(l));
				if_ac[i] = address_ac.Assign(devices_ac[i]);
				address_ac.NewNetwork();
				for (uint32_t j = 0; j < nHost; j++) {
					//cout << i << " : " << j << endl;
					if(i / 2 == j / (nSize*2)){
						//setup ip route
						////configure of core
						cmd_oss.str("");
						cmd_oss << "route add 10." << l + 1 <<"." << j << ".0/24 via " << if_ac[i].GetAddress(0, 0);
						//cmd_oss << "route add 10." << i % 2 + 1 <<"." << j << ".0/24 via " << if_ac[i].GetAddress(0, 0);
						cout <<"core" << l << "  :  " << cmd_oss.str() << endl;
						LinuxStackHelper::RunIp(core.Get(l), Seconds(0.2), cmd_oss.str().c_str());
					}else{
						////configure of edge
						cmd_oss.str("");
						cmd_oss << "route add 10." << l + 1<<"." << j << ".0/24 via " << if_ac[i].GetAddress(1, 0);
						//cmd_oss << "route add 10." << i % 2 + 1 <<"." << j << ".0/24 via " << if_ac[i].GetAddress(1, 0);
						cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
						LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
					}
				}
			}

			/*
			for (uint32_t j = 0; j < nHost; j++) {
				//cout << i << " : " << j << endl;
				if(i / 2 == j / (nSize*2)){
					//setup ip route
					////configure of core
					cmd_oss.str("");
					cmd_oss << "route add 10." << l + 1 <<"." << j << ".0/24 via " << if_ac[i].GetAddress(0, 0);
					//cmd_oss << "route add 10." << i % 2 + 1 <<"." << j << ".0/24 via " << if_ac[i].GetAddress(0, 0);
					cout <<"core" << l << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(core.Get(l), Seconds(0.2), cmd_oss.str().c_str());
				}else{
					////configure of edge
					cmd_oss.str("");
					cmd_oss << "route add 10." << l + 1<<"." << j << ".0/24 via " << if_ac[i].GetAddress(1, 0);
					//cmd_oss << "route add 10." << i % 2 + 1 <<"." << j << ".0/24 via " << if_ac[i].GetAddress(1, 0);
					cout <<"aggr" << i << "  :  " << cmd_oss.str() << endl;
					LinuxStackHelper::RunIp(aggr.Get(i), Seconds(0.2), cmd_oss.str().c_str());
				}
			}*/
			cout << endl;
		}
	}
	//LinuxStackHelper::RunIp (host.Get (0), Seconds (0.1), "rule show");
	//LinuxStackHelper::RunIp (edge.Get (1), Seconds (0.0), "link set dev sim0 multipath on");
	LinuxStackHelper::RunIp(aggr.Get(0), Seconds(0.1),"route delete default scope global nexthop via 10.35.1.2");
	// debug
	stack.SysctlSet(host, ".net.mptcp.mptcp_debug", "1");

	DceApplicationHelper dce;
	ApplicationContainer apps;

	dce.SetStackSize(1 << 20);

	// Launch iperf client 送る側
	dce.SetBinary("iperf");
	dce.ResetArguments();
	dce.ResetEnvironment();
	dce.AddArgument("-c");
	dce.AddArgument("10.3.0.1"); // dist address
	dce.AddArgument("-i");
	dce.AddArgument("1");
	dce.AddArgument("-t");
	dce.AddArgument("5");

	apps = dce.Install(host.Get(0)); //送る側
	apps.Start(Seconds(1.0));
	apps.Stop(Seconds(5));

	// Launch iperf server 受ける側
	dce.SetBinary("iperf");
	dce.ResetArguments();
	dce.ResetEnvironment();
	dce.AddArgument("-s");
	dce.AddArgument("-P");
	dce.AddArgument("1");
	apps = dce.Install(edge.Get(0));

/*
	DceApplicationHelper dce2;
	ApplicationContainer apps2;

	dce2.SetStackSize(1 << 20);

	// Launch iperf client 送る側
	dce2.SetBinary("iperf");
	dce2.ResetArguments();
	dce2.ResetEnvironment();
	dce2.AddArgument("-c");
	dce2.AddArgument("10.3.7.2"); // dist address
	dce2.AddArgument("-i");
	dce2.AddArgument("1");
	dce2.AddArgument("-t");
	dce2.AddArgument("10");

	apps2 = dce2.Install(host.Get(0)); //送る側
	apps2.Start(Seconds(1.0));
	apps2.Stop(Seconds(10));

	// Launch iperf server 受ける側
	dce2.SetBinary("iperf");
	dce2.ResetArguments();
	dce2.ResetEnvironment();
	dce2.AddArgument("-s");
	dce2.AddArgument("-P");
	dce2.AddArgument("1");
	apps2 = dce2.Install(host.Get(7));
*/
	pointToPoint_he.EnablePcapAll("./pcap/sub2/he/iperf-he", false);
	pointToPoint_ea.EnablePcapAll("./pcap/sub2/ea/iperf-ea", false);
	pointToPoint_ac.EnablePcapAll("./pcap/sub2/ac/iperf-ac", false);

	apps.Start(Seconds(1));
	//apps2.Start(Seconds(1));

	for (uint32_t i = 0; i < nHost; i++) {
		setPos(host.Get(i), i * 20 + 5, 0, 0);
	}
	for (uint32_t i = 0; i < nEdge; i++) {
		setPos(edge.Get(i), (i * 40) + 15, 100, 0);
		setPos(aggr.Get(i), (i * 40) + 15, 200, 0);
	}
	for (uint32_t i = 0; i < nCore; i++) {
		setPos(core.Get(i), (i * 80) + 35, 300, 0);
	}

	Simulator::Stop(Seconds(5.0));
	AnimationInterface anim("./xml/mptcp_sub2.xml");
	Simulator::Run();
	Simulator::Destroy();

	return 0;
}
