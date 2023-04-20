#include "Operation.h"
#include "Util.h"
#include "../../include/bluetooth.h"
#include "assert.h"
#include <iostream>
#include <string.h>
#include <string>
#include <set>

using namespace std;

vector<Parameter> parameters;
vector<Operation> operations;

extern vector<Operation*> core_operations; 

set<string> core_parameters = 
{
    OP_PARAMETER_HCI_HANDLE,
    OP_PARAMETER_CID,
    OP_PARAMETER_PSM
};

extern "C" u32 bt_operation_nr()
{
    return operations.size();
}

// u32 Operation::size()
// {
//     u32 n = sizeof(operation_t) + inputs.size() * sizeof(parameter_t);
//     for(Parameter* i : inputs)
//         n += i->bytes;
//     return n;
// }

// u32 Operation::serialize(u8* buf)
// {
//     item_t* item = (item_t*)buf;
//     operation_t* op = (operation_t*)&item->data[0];
//     parameter_t* param = (parameter_t*)&op->data[0];
//     item->size = size();
//     op->flag = OPERATION;
//     op->id = id;
//     op->params = inputs.size();

//     for(Parameter* p : inputs){
//         param->len = p->bytes;
//         memcpy(param->data, p->data, p->bytes);
//         param = (parameter_t*)&param->data[param->len];
//     }
//     return item->size + sizeof(u32);
// }

Parameter *get_parameter(string name)
{
    if (name.find("data") == 0)
    {
        Parameter *param = new Parameter("data", 0);
        param->isEnum = false;
        if (name.find(':') != name.npos)
            sscanf(name.c_str(), "data[%d:%d]", &param->min_bytes, &param->max_bytes);
        else if (name.find('[') != name.npos){
            sscanf(name.c_str(), "data[%d]", &param->min_bytes);
            param->max_bytes = param->min_bytes;
        }
        else{
            param->min_bytes = 1;
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
        if(op.Name() == name)
            return &op;
    return nullptr;
}

Operation* get_operation(u32 id)
{
    for(Operation& op : operations)
        if(op.ID() == id)
            return &op;
    return nullptr;
}

void init_parameters()
{
    parameters.push_back(Parameter(OP_PARAMETER_HCI_HANDLE, OP_PARAMETER_HCI_HANDLE_SIZE));
    parameters.push_back(Parameter(OP_PARAMETER_CID, OP_PARAMETER_CID_SIZE));
    parameters.push_back(Parameter(OP_PARAMETER_PSM, OP_PARAMETER_PSM_SIZE));
}

void init_operations()
{
    // // bd_addr_t, bd_addr_type_t
    // operations.push_back(Operation(CORE_OPERATION_GAP_CONNECT, true));
    // operations.push_back(Operation(CORE_OPERATION_GAP_CONNECT, true));

    // // hci_con_handle_t
    // operations.push_back(Operation(CORE_OPERATION_GAP_DISCONNECT, true));

    // // bd_addr, psm
    // operations.push_back(Operation(CORE_OPERATION_L2CAP_CREATE_CHANNEL, true));

    // //psm, gap_security_level
    // operations.push_back(Operation(CORE_OPERATION_L2CAP_REGISTER_SERVICE, true));    
}

void Operation::deserialize(operation_t* pOp)
{
    parameter_t* pParam = (parameter_t*)pOp->data;
    for(Parameter& p : inputs){
        p.bytes = pParam->len;
        memcpy(p.data, pParam->data, p.bytes);
        pParam = (parameter_t*)&pParam->data[pParam->len];
    }
}

// Generate the concrete value of a parameter
// The length of the parameter should already be determined by Operation::arrange_bytes()
bool Parameter::generate()
{
    bool res = true;
    // bytes = (max_bytes == min_bytes) ? max_bytes : (min_bytes + rand_below(max_bytes - min_bytes));
    // assert(bytes!=0);
    if(isEnum){
        data[0] = rand_below(domain.size());
    }else if(!domain.empty()){
        u32 n = rand_below(domain.size());
        auto v = domain[n];
        memcpy(data, v.data(), bytes);
    }else{
        rand_fill(data, bytes);
        res = (name == OP_PARAMETER_BYTEARRAY);
    }
    return res;
}

Operation* Operation::arrange_bytes(u8* buf)
{
    u32 l = 0;
    pItem = (item_t*)buf;
    pOp = (operation_t*)&pItem->data[0];
    parameter_t* param = (parameter_t*)&pOp->data[0];
    pOp->flag = OPERATION;
    pOp->id = id;
    pOp->params = inputs.size();

    for(Parameter& p : inputs){
        if(p.max_bytes == p.min_bytes)
            param->len = p.bytes = p.max_bytes;
        else
            param->len = p.bytes = rand_below(p.max_bytes - p.min_bytes) + p.min_bytes;
        p.data = param->data;
        l += (p.bytes + sizeof(parameter_t));
        param = (parameter_t*)&param->data[param->len];
    }
    pItem->size =  sizeof(operation_t) + l;
    return this;
}