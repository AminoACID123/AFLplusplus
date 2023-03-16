#include "cJSON.h"
#include "Hci.h"
#include "Parse.h"
using namespace std;

ostream & operator << (ostream &out, HCIParameter& p)
{
    out << "Name: " << p.name << endl;
    out << "Size: " << p.size << endl;
    return out;
}


ostream& operator << (std::ostream &out, HCICommand& c)
{
    out << "Name: " << c.name << std::endl;
    out << "OGF: " << (u32)c.ogf << std::endl;
    out << "OCF: " << (u32)c.ocf[0][0] << std::endl;
    for (HCIParameter& param : c.p) {
      out << param;
    }
    return out;
}

void parse_parameters(cJSON* root, std::vector<HCIParameter>& params) {
    cJSON *jParam, *jDomain, *jDomains;
    cJSON_ArrayForEach(jParam, root) 
    {
        HCIParameter param;
        param.setName(jParam->string);
        param.setSize(cJSON_GetObjectItem(jParam, "size")->valueint);
        jDomains = cJSON_GetObjectItem(jParam, "domain");
        cJSON_ArrayForEach(jDomain, jDomains)
        {
            if(cJSON_GetArraySize(jDomain) == 0)
                param.addDomain();
            else{
                u32 a = cJSON_GetArrayItem(jDomain, 0)->valueint;
                u32 b = cJSON_GetArrayItem(jDomain, 1)->valueint;
                param.addDomain(a, b); 
            }
        }
        params.push_back(param);
    }
}


void parse_commands(cJSON* root) {
    cJSON* item;
    cJSON* commands =  cJSON_GetObjectItem(root, "commands");
    HCIManager* manager = HCIManager::get();
    cJSON_ArrayForEach(item, commands) 
    {
        cJSON *jOcfs, *jOcf; 
        cJSON *jParams, *jParam, *jRparams, *jRparam;
        HCICommand cmd;
        cmd.setName(cJSON_GetObjectItem(item, "name")->valuestring);
        cmd.setOgf(cJSON_GetObjectItem(item, "ogf")->valueint);
        jOcfs = cJSON_GetObjectItem(item, "ocf");
        cJSON_ArrayForEach(jOcf, jOcfs) 
        {
            u8 c = cJSON_GetArrayItem(jOcf, 0)->valueint;
            u8 n1 = cJSON_GetArrayItem(jOcf, 1)->valueint;
            u8 n2 = cJSON_GetArrayItem(jOcf, 2)->valueint;
            cmd.addOcf(c, n1, n2);
        }
        
        jParams = cJSON_GetObjectItem(item, "p");
        jRparams = cJSON_GetObjectItem(item, "rp");
        parse_parameters(jParams, cmd.getParameters());
        parse_parameters(jRparams, cmd.getRParameters());
        manager->addCommand(cmd);
    }
}


void parse_events(cJSON* root) {
    cJSON* item;
    cJSON* events =  cJSON_GetObjectItem(root, "commands");
    HCIManager* manager = HCIManager::get();
    cJSON_ArrayForEach(item, events)
    {
        cJSON *jOpcs, *jOpc, *jParams;
        HCIEvent event;
        event.setName(cJSON_GetObjectItem(item, "name")->valuestring);
        jOpcs = cJSON_GetObjectItem(item, "opcode");
        cJSON_ArrayForEach(jOpc, jOpcs)
        {
            u8 c = cJSON_GetArrayItem(jOpc, 0)->valueint;
            u8 n = cJSON_GetArrayItem(jOpc, 1)->valueint;
            event.addOpcode(c, n);      
        }
        jParams = cJSON_GetObjectItem(item, "p");
        parse_parameters(jParams, event.getParameters());
        manager->addEvent(event);
    }
}


void parse_hci(const char* file) {
    cJSON* json = load_from_file(file);
    parse_commands(json);
    parse_events(json);
}

int main(int argc, char** argv)
{
    parse_hci(argv[1]);
    return 0;
}