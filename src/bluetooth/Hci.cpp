#include "cJSON.h"
#include "Hci.h"
#include "Parse.h"
using namespace std;

HCIManager* HCIManager:: manager = nullptr;

u16 hci_handle;
u8 bd_addr[6];

ostream & operator << (ostream &out, HCIParameter& p)
{
    out << "Name: " << p.name << endl;
    out << "Size: " << p.size << endl;
    return out;
}

ostream& operator << (std::ostream &out, HCICommand& c)
{
    out << "Name: " << c.name << std::endl;
    out << "OGF: " << (u32)c.OGF << std::endl;
    out << "OCF: " << (u32)c.OCF[0][0] << std::endl;
    for (HCIParameter& param : c.params) {
      out << param;
    }
    return out;
}


void HCICommand::serialize(u8* buf, u8 ogf, u8 ocf) 
{
    item_t* pItem;
    u8 *pParam;
    hci_command_t* pCmd;
    
    pItem = (item_t*)buf;
    pCmd = (hci_command_t*)pItem->data;
    pParam = (u8*)pCmd->param;

    pCmd->flag = HCI_COMMAND_DATA_PACKET;
    pCmd->opcode = HCI_OPCODE(ogf, ocf);
    pCmd->len = 0;
    for(vector<u8>& arg : args){
        memcpy(pParam, arg.data(), arg.size());
        pParam += arg.size();
        pCmd->len += arg.size();
    }
    pItem->size = sizeof(hci_command_t) + pCmd->len;
}

void HCICommand::deserialize(u8* buf)
{
    item_t* pItem;
    u8 *pParam;
    hci_command_t* pCmd;

    args.clear();
    
    pItem = (item_t*)buf;
    pCmd = (hci_command_t*)pItem->data;
    pParam = (u8*)pCmd->param;

}


void HCIEvent::serialize(u8* buf, u8 opc) 
{
    item_t* pItem;
    u8 *pParam;
    hci_event_t* pEvent;
    
    pItem = (item_t*)buf;
    pEvent = (hci_event_t*)pItem->data;
    pParam = (u8*)pEvent->param;

    pEvent->flag = HCI_EVENT_PACKET;
    pEvent->opcode = opc;
    pEvent->len = 0;
    for(vector<u8>& arg : args)
    {
        memcpy(pParam, arg.data(), arg.size());
        pParam += arg.size();
        pEvent->len += arg.size();
    }
    pItem->size = sizeof(hci_event_t) + pEvent->len;
}


void parse_parameters(cJSON* root, std::vector<HCIParameter>& params) 
{
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
        cJSON *jOCFs, *jOCF; 
        cJSON *jParams, *jParam, *jRparams, *jRparam;
        cJSON *jEvent, *jEvents;
        HCICommand cmd;
        cmd.setName(cJSON_GetObjectItem(item, "name")->valuestring);
        cmd.setOGF(cJSON_GetObjectItem(item, "ogf")->valueint);
        jOCFs = cJSON_GetObjectItem(item, "ocf");
        cJSON_ArrayForEach(jOCF, jOCFs) 
        {
            u8 c = cJSON_GetArrayItem(jOCF, 0)->valueint;
            u8 n1 = cJSON_GetArrayItem(jOCF, 1)->valueint;
            u8 n2 = cJSON_GetArrayItem(jOCF, 2)->valueint;
            cmd.addOCF(c, n1, n2);
        }

        jEvents = cJSON_GetObjectItem(item, "events");
        cJSON_ArrayForEach(jEvent, jEvents) 
        {  
            string event = jEvent->valuestring;
            if(event == HCI_COMMAND_COMPLETE)
                cmd.setResponseType(HCICommand::COMPLETE);
            else if (event == HCI_COMMAND_STATUS)
                cmd.setResponseType(HCICommand::STATUS);
            else
                cmd.addEvent(manager->getEvent(event));
        }
        
        jParams = cJSON_GetObjectItem(item, "p");
        jRparams = cJSON_GetObjectItem(item, "rp");
        parse_parameters(jParams, cmd.getParams());
        parse_parameters(jRparams, cmd.getReturnParams());
        manager->addCommand(cmd);
    }
}

void parse_events(cJSON* root) {
    cJSON* item;
    cJSON* events =  cJSON_GetObjectItem(root, "events");
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
        parse_parameters(jParams, event.getParams());
        manager->addEvent(event);
    }
}


void parse_hci(const char* file) {
    cJSON* json = load_from_file(file);
    parse_events(json);
    parse_commands(json);
}

int main(int argc, char** argv)
{
    parse_hci(argv[1]);
    return 0;
}