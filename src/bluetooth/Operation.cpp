#include "Operation.h"
#include "CoreOperation.h"
#include "../../include/bluetooth.h"
#include <string>
#include <set>

using namespace std;

vector<Parameter> parameters;
vector<Operation> operations;

set<string> core_operations = 
{
    CORE_OPERATION_GAP_CONNECT,
    CORE_OPERATION_GAP_CONNECT_CANCEL,
    CORE_OPERATION_GAP_DISCONNECT,
    CORE_OPERATION_L2CAP_CREATE_CHANNEL,
    CORE_OPERATION_L2CAP_REGISTER_SERVICE
};

set<string> core_parameters = 
{
    CORE_PARAMETER_BD_ADDR,
    CORE_PARAMETER_HCI_HANDLE,
    CORE_PARAMETER_BD_ADDR_TYPE,
    CORE_PARAMETER_CID,
    CORE_PARAMETER_PSM,
    CORE_PARAMETER_SECURITY_LEVEL
};

u32 Operation::size()
{
    u32 n = sizeof(operation_header) + inputs.size() * sizeof(parameter_header);
    for(Parameter* i : inputs)
        n += i->bytes;
    return n;
}

Parameter *get_parameter(string name)
{
    if (name.find("data") == 0)
    {
        Parameter *param = new Parameter("data", 0);
        param->isEnum = false;
        if (name.find(':') != name.npos)
            sscanf(name.c_str(), "data[%d:%d]", &param->min_bytes, &param->max_bytes);
        else if (name.find('[') != name.npos)
            sscanf(name.c_str(), "data[%d]", &param->bytes);
        else{
            param->min_bytes = 0;
            param->max_bytes = BT_MAX_PARAM_SIZE;
        }
        return param;
    }

    for (Parameter& param : parameters){
        if (name == param.name)
            return &param;
    }
    return nullptr;
}

Operation* get_operation(string name)
{
    for(Operation& op : operations)
        if(op.name == name)
            return &op;
    return nullptr;
}


void init_parameters()
{
    parameters.push_back(Parameter(CORE_PARAMETER_BD_ADDR, CORE_PARAMETER_BD_ADDR_SIZE));
    parameters.push_back(Parameter(CORE_PARAMETER_HCI_HANDLE, CORE_PARAMETER_HCI_HANDLE_SIZE));
    parameters.push_back(Parameter(CORE_PARAMETER_BD_ADDR_TYPE, CORE_PARAMETER_BD_ADDR_TYPE_SIZE));
    parameters.push_back(Parameter(CORE_PARAMETER_CID, CORE_PARAMETER_CID_SIZE));
    parameters.push_back(Parameter(CORE_PARAMETER_PSM, CORE_PARAMETER_PSM_SIZE));
    parameters.push_back(Parameter(CORE_PARAMETER_SECURITY_LEVEL, CORE_PARAMETER_SECURITY_LEVEL_SIZE));
}

void init_operations()
{
    // bd_addr_t, bd_addr_type_t
    operations.push_back(Operation(CORE_OPERATION_GAP_CONNECT, true));
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_BD_ADDR));
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_BD_ADDR_TYPE));          
    
    operations.push_back(Operation(CORE_OPERATION_GAP_CONNECT, true));

    // hci_con_handle_t
    operations.push_back(Operation(CORE_OPERATION_GAP_DISCONNECT, true));
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_HCI_HANDLE));

    // bd_addr, psm
    operations.push_back(Operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL, true));
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_BD_ADDR));
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_PSM));    

    //psm, gap_security_level
    operations.push_back(Operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL, true));
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_PSM)); 
    operations.back().inputs.push_back(get_parameter(CORE_PARAMETER_SECURITY_LEVEL));       
}

