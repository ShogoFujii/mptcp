#include <iostream>
#include <cstdlib>
#include <map>
#include <string.h>
#include <math.h>
#include <sstream>
#include <vector>
#include <algorithm>

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
NS_LOG_COMPONENT_DEFINE ("DceIperfMptcp");
//--declare--//
void setPos(Ptr<Node> n, int x, int y, int z);
void iperf(multimap<int, string> &ip_set, double start, double end, NodeContainer host);
void socketTraffic(multimap<int, string> &ip_set, uint32_t byte, double start, double end, NodeContainer nodes);
void makebox(int *box, int size);
void shuffle(int *box, int size);
void map_insert(multimap<int, string> &adrs_set, int *box, int size, double ratio, int path_num);
int host_detect(char *adrs);
string double2string(double d);
string int2string(int d);
char* string2char(string s);
string fix_adrs(char *adrs, int path);

//--script--//

void makebox(int *box, int size){
	int i;
	for(i=0; i < size; i++){
		box[i]=i;
	}
}

void shuffle(int *box, int size){
	int i;
	makebox(box, size);
	int pre_box[size];
	//srand((unsigned) time(NULL));
	memcpy(pre_box, box, sizeof(int) *size);
	int count=0;
	while(count != size){
		count = 0;
		for(i=0; i < size; i++){
			int r = rand() % size;
			if(pre_box[i]/4 != box[r]/4 and pre_box[i] != box[r]){
				int m = box[i];
				box[i] = box[r];
				box[r] = m;
				count++;
			}
		}
	}
}
void shuffle2(int *box, int size){
	int i;
	int pre_box[size];
	memcpy(pre_box, box, sizeof(int) *size);
	int count=0;
	while(count != size){
		count = 0;
		for(i=0; i < size; i++){
			int r = rand() % size;
			if(pre_box[i]/4 != box[r]/4 and pre_box[i] != box[r]){
				//cout << "pre_box[i] : " << pre_box[i] << endl;
				int m = box[i];
				box[i] = box[r];
				box[r] = m;
				count++;
			}
		}
	}
}
void randomize_box(int *box, int box_size,  multimap<int, string> &adrs_set){
	int size = box_size;
	string tmp;
	int pre_box[size];
	memcpy(pre_box, box, sizeof(int) *size);
	shuffle2(box, size);
	for(int i=0; i < size; i++){
		tmp = "10." + int2string(box[i]/4 + 1) + "." + int2string(box[i]) + ".2";
		adrs_set.insert(map<int, string>::value_type(pre_box[i], tmp));
	}
}

void init_rand(){
	srand((unsigned) time(NULL));
}
void randomize_box2(int *box, int box_size,  map<int, string> &adrs_set){
	int size = box_size;
	string tmp;
	int pre_box[size];
	memcpy(pre_box, box, sizeof(int) *size);
	shuffle2(box, size);
	for(int i=0; i < size; i++){
		tmp = "10." + int2string(box[i]/4 + 1) + "." + int2string(box[i]) + ".2";
		adrs_set.insert(map<int, string>::value_type(pre_box[i], tmp));
	}
}


bool random_slot(double ratio){
	//cout << rand() % 100 << endl;
	if (rand() % 100 < ratio * 100){
		return true;
	}
	return false;
}

void map_insert(multimap<int, string> &adrs_set, int *box, int size, double ratio, int path_num){
	int i;
	int subnet;
	ostringstream ip;
	for(i=0; i < size; i++){
		ip.str("");
		if (random_slot(ratio) == true){
			if(i != box[i]){
				subnet=box[i] / 4 + 1;
				if(path_num == 2){
					if(subnet == 2){
						subnet=1;
					}else if(subnet == 4){
						subnet=3;
					}
				}else if(path_num == 3){
					if(subnet == 4){
						subnet = 3;
					}
				}
				ip << "10." << subnet  << "."  << box[i] << ".2" ;
				adrs_set.insert(map<int, string>::value_type(i, ip.str()));
			}
		}
	}
}
void show_multimap(multimap<int, string> &adrs_set){
	multimap<int, string>::iterator it = adrs_set.begin();
	while(it != adrs_set.end()){
		cout << "From host" << (*it).first << ": [Dest_IP]" << (*it).second << endl;
		++it;
	}
	cout << "Total patterns : " << (unsigned int)adrs_set.size() << endl;
}
void show_map(map<int, string> &adrs_set){
	map<int, string>::iterator it = adrs_set.begin();
	while(it != adrs_set.end()){
		cout << "From host" << (*it).first << ": [Dest_IP]" << (*it).second << endl;
		++it;
	}
	cout << "Total patterns : " << (unsigned int)adrs_set.size() << endl;
}

int host_detect(char *adrs){
	const char delm[] = ".";
	char *tok;
	int host;

	tok = strtok(adrs, delm);
	int j = 0;
	while(tok != NULL){
		if(j == 1){
			host = atoi(tok)-1;
			break;
		}
		tok = strtok(NULL, delm);
		j++;
	}
	return host;
}

string double2string(double d){
	string rt;
	stringstream ss;
	ss << d;
	ss >> rt;
	return rt;
}

string int2string(int d){
	string rt;
	stringstream ss;
	ss << d;
	ss >> rt;
	return rt;
}

char* string2char(string s){
	int len = s.length();
	char* c = new char[len+1];
	memcpy(c, s.c_str(), len+1);
	return c;
}
string fix_adrs(char *adrs, int path){
	const char delm[] = ".";
	char *tok;
	int post;
	int host;
	string fix="";

	tok = strtok(adrs, delm);
	int j = 0;
	while(tok != NULL){
		if(j == 1){
			host = atoi(tok);
		}else if(j == 2){
			post = atoi(tok);
		}
		tok = strtok(NULL, delm);
		j++;
	}
	if(path == 2){
		if(host == 2){
			host = 1;
		}else if (host == 4){
			host = 3;
		}
	}else if (path == 3){
		if(host == 4){
			host = 3;
		}
	}
	fix=fix+"10."+int2string(host)+"."+int2string(post)+".2";
	return fix;
}
void map_slice(multimap<int, string> &adrs_set, map<int, string> &adrs_back, double ratio){
	int size = (int) adrs_set.size();
	int box[size];
	shuffle(box, size);
	int bound = (int) ((int) adrs_set.size()*ratio);
	map<int, string>::iterator it;
	for(int k=0;k < bound;k++){
		it = adrs_set.find(box[k]);
		adrs_back.insert(map<int, string>::value_type(box[k], (*it).second));
	}
}
void iperf(multimap<int, string> &ip_set, double start, double end, NodeContainer host){
	int tasks = ip_set.size();
	
	DceApplicationHelper dce[tasks];
	ApplicationContainer apps[tasks];
	
	multimap<int, string>::iterator it = ip_set.begin();
	int i = 0;
	int time = (int) end - start;
	time = time +1;
	while(it != ip_set.end()){
		dce[i].SetStackSize(1 << 20);

		// Launch iperf client 送る側
		dce[i].SetBinary("iperf");
		dce[i].ResetArguments();
		dce[i].ResetEnvironment();
		dce[i].AddArgument("-c");
		dce[i].AddArgument((*it).second); // dist address
		dce[i].AddArgument("-i");
		dce[i].AddArgument("1");
		dce[i].AddArgument("--time");
		dce[i].AddArgument(int2string(time));
		cout << "-c " << (*it).second << " --time " << int2string(time) << " host:" << (*it).first << " start: " << start << " end: " << end << endl;
		apps[i] = dce[i].Install(host.Get((*it).first)); //送る側
		apps[i].Start(Seconds(start));
		apps[i].Stop(Seconds(end));

		// Launch iperf server 受ける側
		dce[i].SetBinary("iperf");
		dce[i].ResetArguments();
		dce[i].ResetEnvironment();
		dce[i].AddArgument("-s");
		dce[i].AddArgument("-P");
		dce[i].AddArgument("1");
		int ser = host_detect(string2char((*it).second));
		apps[i] = dce[i].Install(host.Get(ser));
		cout << "client:" << ser << endl;
		++it;
		i++;
	}
	
	for(i=0;i<tasks;i++){
		apps[i].Start(Seconds(start));
	}
	//apps[0].Start(Seconds(1));
}

void socketTraffic(multimap<int, string> &ip_set, uint32_t byte, double start, double end, NodeContainer nodes){
	uint32_t size = byte;
		if (byte != 0){
			size = byte * 1000 - 1502;
		}
	int tasks = ip_set.size();
	ApplicationContainer apps[tasks], sinkApps[tasks];
	multimap<int, string>::iterator it = ip_set.begin();	
	string sock_factory = "ns3::LinuxTcpSocketFactory";
	int i = 0;
	while(it != ip_set.end()){
		//BulkSendHelper bulk[i];
		//cout << "IP : " << (*it).second << endl;
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

int* poisson_pros(int sec, int end_time, int freq, int *poisson_size){
	int total_queue=0, queue=0;
	int random;
	int *pre_set;
	pre_set = new int[5000];
	int k=0;
	srand((unsigned) time(NULL));
	while(sec < end_time){
		queue = 0;
		random = rand() % 100 + 1;
		if(random < freq){
			queue++;
		}
		if(queue != 0){
			pre_set[k]=sec;
			//cout << sec << "[msec]" << queue << endl;
			k++;
		}
		sec=sec+10;
		//cout << sec << endl;
		total_queue += queue;
	}
	int *poisson_set;
	poisson_set = new int[k];
	for(int i=0;i < k;i++){
		poisson_set[i]=pre_set[i];
		cout << i << " : " << poisson_set[i] << endl;
	}
	*poisson_size = k;
	delete[] pre_set;
	return poisson_set;
}

int* constant_pros(int sec, int end_time, int freq, int *poisson_size){
	int total_queue=0, queue=0;
	int random;
	int *pre_set;
	pre_set = new int[5000];
	int k=0;
	int interval = 10 * freq;
	srand((unsigned) time(NULL));
	while(sec < end_time){
		pre_set[k]=sec;
		k++;
		sec=sec+interval;
	}
	int *poisson_set;
	poisson_set = new int[k];
	for(int i=0;i < k;i++){
		poisson_set[i]=pre_set[i];
		cout << i << " : " << poisson_set[i] << endl;
	}
	*poisson_size = k;
	delete[] pre_set;
	return poisson_set;
}
void setPos (Ptr<Node> n, int x, int y, int z)
{
  Ptr<ConstantPositionMobilityModel> loc = CreateObject<ConstantPositionMobilityModel> ();
  n->AggregateObject (loc);
  Vector locVec2 (x, y, z);
  loc->SetPosition (locVec2);
}
void
PrintTcpFlags (std::string key, std::string value)
{
  NS_LOG_INFO (key << "=" << value);
}


int main (int argc, char *argv[])
{
  uint32_t nRtrs = 4;
  uint32_t nNodes = 3;
  uint32_t s_size = 70; 
  uint32_t nDir_name = 1;
  double end = 8.0;

  CommandLine cmd;
  cmd.AddValue ("nRtrs", "Number of routers. Default 2", nRtrs);
  cmd.AddValue ("nNodes", "Number of routers. Default 3", nNodes);
  cmd.AddValue ("nDir", "the place of pcap files", nDir_name);
  cmd.AddValue ("s_size", "Traffic size in short flow", s_size);
  cmd.Parse (argc, argv);

  NodeContainer nodes, routers, routers2;
  int nodes_num=nNodes * 2;
  nodes.Create (nodes_num);
  routers.Create (nRtrs);
  routers2.Create (nRtrs);

  DceManagerHelper dceManager;
  dceManager.SetTaskManagerAttribute ("FiberManagerType",
                                      StringValue ("UcontextFiberManager"));

  dceManager.SetNetworkStack ("ns3::LinuxSocketFdFactory",
                              "Library", StringValue ("liblinux.so"));
  LinuxStackHelper stack;
  stack.Install (nodes);
  stack.Install (routers);
  stack.Install (routers2);

  dceManager.Install (nodes);
  dceManager.Install (routers);
  dceManager.Install (routers2);

  PointToPointHelper pointToPoint;
  NetDeviceContainer devices[nodes_num+1];
  Ipv4AddressHelper address_list[nodes_num+1];

  std::ostringstream cmd_oss;
  for (int j=0; j < nodes_num+1; j++){
    cmd_oss.str ("");
    cmd_oss << "10." << j+1 << ".0.0";
  	address_list[j].SetBase (cmd_oss.str().c_str(), "255.255.255.0");
  }
  Ipv4InterfaceContainer ifc[nodes_num+1];

  for (uint32_t i = 0; i < nRtrs; i++)
    {
      // Left link
      pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
      pointToPoint.SetChannelAttribute ("Delay", StringValue ("1ns"));
      //pointToPoint.SetChannelAttribute ("Delay", TimeValue(MicroSeconds(0)));
	  for (int j=0; j < nodes_num/2; j++){
	  	devices[j*2] = pointToPoint.Install (nodes.Get (j*2), routers.Get (i));
        ifc[j*2] = address_list[j*2].Assign (devices[j*2]);
      	address_list[j*2].NewNetwork ();
		
        cmd_oss.str ("");
        cmd_oss << "rule add from " << ifc[j*2].GetAddress (0, 0) << " table " << (i+1);
        LinuxStackHelper::RunIp (nodes.Get (j*2), Seconds (0.1), cmd_oss.str ().c_str ());
		cout << cmd_oss.str ().c_str () << endl;
        cmd_oss.str ("");
        cmd_oss << "route add 10." << j*2+1  <<"." << i << ".0/24 dev sim" << i << " scope link table " << (i+1);
        LinuxStackHelper::RunIp (nodes.Get (j*2), Seconds (0.1), cmd_oss.str ().c_str ());
		cout << cmd_oss.str ().c_str () << endl;
        cmd_oss.str ("");
        cmd_oss << "route add default via " << ifc[j*2].GetAddress (1, 0) << " dev sim" << i << " table " << (i+1);
        LinuxStackHelper::RunIp (nodes.Get (j*2), Seconds (0.1), cmd_oss.str ().c_str ());
		cout << cmd_oss.str ().c_str () << endl;
        cmd_oss.str ("");
        cmd_oss << "route add 10." << j*2+1 << ".0.0/16 via " << ifc[j*2].GetAddress (1, 0) << " dev sim0";
        LinuxStackHelper::RunIp (routers.Get (i), Seconds (0.2), cmd_oss.str ().c_str ());
		cout << cmd_oss.str ().c_str () << endl;
	  }
	  cout << endl;

      // middle link
      pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("200Mbps"));
      //pointToPoint.SetChannelAttribute ("Delay", StringValue ("1ns"));
      pointToPoint.SetChannelAttribute ("Delay", TimeValue(MicroSeconds(25)));
      devices[nodes_num] = pointToPoint.Install (routers.Get (i), routers2.Get (i));
      // Assign ip addresses
      ifc[nodes_num] = address_list[nodes_num].Assign (devices[nodes_num]);
      address_list[nodes_num].NewNetwork ();
      // setup ip routes
	  
	  for (int j=0; j < nodes_num/2; j++){
      	cmd_oss.str ("");
      	cmd_oss << "route add 10." << (j+1)*2  << ".0.0/16 via " << ifc[nodes_num].GetAddress (1, 0) ;
      	LinuxStackHelper::RunIp (routers.Get (i), Seconds (0.1), cmd_oss.str ().c_str ());
		cout << cmd_oss.str ().c_str () << endl;
      	cmd_oss.str ("");
      	cmd_oss << "route add 10." << j*2+1 << ".0.0/16 via " << ifc[nodes_num].GetAddress (0, 0) ;
      	LinuxStackHelper::RunIp (routers2.Get (i), Seconds (0.2), cmd_oss.str ().c_str ());
		cout << cmd_oss.str ().c_str () << endl;
      }
	  cout << endl;

      // Right link
      pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
      pointToPoint.SetChannelAttribute ("Delay", StringValue ("1ns"));
      //pointToPoint.SetChannelAttribute ("Delay", TimeValue(MicroSeconds(0)));
	  for (int j=0; j < nodes_num/2; j++){
	  	devices[j*2+1] = pointToPoint.Install (nodes.Get (j*2+1), routers2.Get (i));
        ifc[j*2+1] = address_list[j*2+1].Assign (devices[j*2+1]);
      	address_list[j*2+1].NewNetwork ();
		
        cmd_oss.str ("");
        cmd_oss << "rule add from " << ifc[j*2+1].GetAddress (0, 0) << " table " << (i+1);
		cout << cmd_oss.str ().c_str () << endl;
        LinuxStackHelper::RunIp (nodes.Get (j*2+1), Seconds (0.1), cmd_oss.str ().c_str ());
        cmd_oss.str ("");
        cmd_oss << "route add 10." << (j+1)*2  <<"." << i << ".0/24 dev sim" << i << " scope link table " << (i+1);
		cout << cmd_oss.str ().c_str () << endl;
        LinuxStackHelper::RunIp (nodes.Get (j*2+1), Seconds (0.1), cmd_oss.str ().c_str ());
        cmd_oss.str ("");
        cmd_oss << "route add default via " << ifc[j*2+1].GetAddress (1, 0) << " dev sim" << i << " table " << (i+1);
		cout << cmd_oss.str ().c_str () << endl;
        LinuxStackHelper::RunIp (nodes.Get (j*2+1), Seconds (0.1), cmd_oss.str ().c_str ());
        cmd_oss.str ("");
        cmd_oss << "route add 10." << (j+1)*2 << ".0.0/16 via " << ifc[j*2+1].GetAddress (1, 0) << " dev sim1";
		cout << cmd_oss.str ().c_str () << endl;
        LinuxStackHelper::RunIp (routers2.Get (i), Seconds (0.2), cmd_oss.str ().c_str ());
	  }
	  
	  cout << endl;
      setPos (routers.Get (i), 30, i * 20, 0);
      setPos (routers2.Get (i), 70, i * 20, 0);
    }

  // default route
  for (int j=0; j < nodes_num; j++){	
        cmd_oss.str ("");
        cmd_oss << "route add default via 10." << j+1 << ".0.2 dev sim0";
  		LinuxStackHelper::RunIp (nodes.Get (j), Seconds (0.1), cmd_oss.str ().c_str ());
  }
  //stack.SysctlSet(nodes, ".net.ipv4.tcp_congestion_control", "olia");
  /*
  linuxstackhelper::runip (nodes.get (0), seconds (0.1), "route add default via 10.1.0.2 dev sim0");
  LinuxStackHelper::RunIp (nodes.Get (1), Seconds (0.1), "route add default via 10.2.0.2 dev sim0");
  LinuxStackHelper::RunIp (nodes.Get (2), Seconds (0.1), "route add default via 10.3.0.2 dev sim0");
  LinuxStackHelper::RunIp (nodes.Get (3), Seconds (0.1), "route add default via 10.4.0.2 dev sim0");
  LinuxStackHelper::RunIp (nodes.Get (4), Seconds (0.1), "route add default via 10.5.0.2 dev sim0");
  LinuxStackHelper::RunIp (nodes.Get (5), Seconds (0.1), "route add default via 10.6.0.2 dev sim0");
  */
  //LinuxStackHelper::RunIp (nodes.Get (0), Seconds (0.1), "rule show");

  for (int i=0; i < nRtrs; i++){	
  	for (int j=0; j < nodes_num+1; j++){	
  	  cmd_oss.str ("");
  	  cmd_oss << "link set sim" << j << " txqueue 100";
	  LinuxStackHelper::RunIp (routers.Get (i), Seconds (0.1), cmd_oss.str().c_str ());
	  LinuxStackHelper::RunIp (routers2.Get (i), Seconds (0.1), cmd_oss.str().c_str ());
	}
	LinuxStackHelper::RunIp (routers.Get (i), Seconds (0.3), "addr show");
	LinuxStackHelper::RunIp (routers2.Get (i), Seconds (0.3), "addr show");
  }
  // Schedule Up/Down (XXX: didn't work...)
  /*
  LinuxStackHelper::RunIp (nodes.Get (1), Seconds (1.0), "link set dev sim0 multipath off");
  LinuxStackHelper::RunIp (nodes.Get (1), Seconds (15.0), "link set dev sim0 multipath on");
  LinuxStackHelper::RunIp (nodes.Get (1), Seconds (30.0), "link set dev sim0 multipath off");
  */

  // debug
  stack.SysctlSet (nodes, ".net.mptcp.mptcp_debug", "1");

  stack.SysctlSet(nodes, ".net.ipv4.tcp_rmem", "5000000 5000000 5000000");
  stack.SysctlSet(nodes, ".net.ipv4.tcp_wmem", "5000000 5000000 5000000");
  stack.SysctlSet(nodes, ".net.core.rmem_max", "5000000");
  stack.SysctlSet(nodes, ".net.core.wmem_max", "5000000");
  //LinuxStackHelper::SysctlGet (nodes.Get (0), Seconds (1), ".net.ipv4.tcp_available_congestion_control", &PrintTcpFlags);


  DceApplicationHelper dce;
  ApplicationContainer apps;

  dce.SetStackSize (1 << 20);

  // Launch iperf client on node 0
  dce.SetBinary ("iperf");
  dce.ResetArguments ();
  dce.ResetEnvironment ();
  dce.AddArgument ("-c");
  dce.AddArgument ("10.2.0.1");
  dce.AddArgument ("-i");
  dce.AddArgument ("1");
  dce.AddArgument ("--time");
  dce.AddArgument ("100");

  apps = dce.Install (nodes.Get (0));
  //apps.Start (Seconds (4.5));
  //apps.Stop (Seconds (10));

  // Launch iperf server on node 1
  dce.SetBinary ("iperf");
  dce.ResetArguments ();
  dce.ResetEnvironment ();
  dce.AddArgument ("-i");
  dce.AddArgument ("1");
  dce.AddArgument ("-s");
  dce.AddArgument ("-P");
  dce.AddArgument ("1");
  apps = dce.Install (nodes.Get (1));
  
  string pcap_place = "./pcap/iperf-mptcp_expe/" + int2string(nDir_name)  + "/iperf-mptcp";
  pointToPoint.EnablePcapAll (pcap_place, false);

  //apps.Start (Seconds (4));

  int sum_tr = 8;
  multimap<int, string> adrs_set, adrs_set2, adrs_set3;
  for (int j=0;j < sum_tr; j++){
  	adrs_set.insert(map<int, string>::value_type(j*2, "10.2.0.1"));
  }
  adrs_set2.insert(map<int, string>::value_type(2, "10.2.0.1"));
  //adrs_set3.insert(map<int, string>::value_type(4, "10.4.0.1"));
  adrs_set3.insert(map<int, string>::value_type(0, "10.2.0.1"));
  //show_multimap(adrs_set);
  int poisson_size, constant_size;
  int *poisson_set = poisson_pros(5000, 7000, 100, &poisson_size);
  int *constant_set = constant_pros(5000, 7000, 100, &constant_size);
  
  for(int i=0; i<constant_size;i++){
    //socketTraffic(adrs_set, s_size, (double) constant_set[i] / 1000, end, nodes);
    //socketTraffic(adrs_set2, s_size, (double) constant_set[i] / 1000, end, nodes);
    //socketTraffic(adrs_set3, s_size, (double) constant_set[i] / 1000, end, nodes);
  }
  
  /*
  for(int i=0; i<poisson_size;i++){
    socketTraffic(adrs_set2, s_size, (double) poisson_set[i] / 1000, end, nodes);
  }
  */
  
  //socketTraffic(adrs_set, 0, 4.0, end, nodes); 
  socketTraffic(adrs_set3, 0, 4.0, end, nodes);
  for (int j=0; j < nodes_num/2; j++){
  	if(nodes_num % 4 != 0){
  			setPos (nodes.Get (j*2), 0, 20 * (nRtrs - 1) / 2 +(nodes_num/4 - j)*20, 0);
  			setPos (nodes.Get (j*2+1), 100, 20 * (nRtrs - 1) / 2 +(nodes_num/4 - j)*20, 0);
	}else{
  			setPos (nodes.Get (j*2), 0, 20 * (nRtrs - 1) / 2 +(nodes_num/4 - j)*20 - 10, 0);
  			setPos (nodes.Get (j*2+1), 100, 20 * (nRtrs - 1) / 2 +(nodes_num/4 - j)*20 - 10, 0);
	}
  }
  /*
  setPos (nodes.Get (0), 0, 20 * (nRtrs - 1) / 2 + 20, 0);
  setPos (nodes.Get (1), 100, 20 * (nRtrs - 1) / 2 + 20, 0);
  setPos (nodes.Get (2), 0, 20 * (nRtrs - 1) / 2 , 0);
  setPos (nodes.Get (3), 100, 20 * (nRtrs - 1) / 2 , 0);
  setPos (nodes.Get (4), 0, 20 * (nRtrs - 1) / 2 - 20, 0);
  setPos (nodes.Get (5), 100, 20 * (nRtrs - 1) / 2 - 20, 0);
  */
  Simulator::Stop (Seconds (end));
  AnimationInterface anim("./xml/dce-iperf-mptcp_expe.xml");
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
