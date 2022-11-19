#ifndef _YAML_CONVERT_H_
#define _YAML_CONVERT_H_

#include <iostream>
#include <string>
#include <vector>
#include <stdio.h>
#include <yaml-cpp/yaml.h>
#include <assert.h>



std::vector<std::string> split(std::string str, std::string pattern)
{
    // std::string::size_type pos;
    std::vector<std::string> result;
    str += pattern;
    int start_pos=0;
    int end_pos;

    int size = str.size();

    for (int i = 1; i < size; i++)
    {
        end_pos = str.find(pattern, i);
        // if(end_pos==0)
        //     break;
        if (end_pos < size)
        {
            std::string s = str.substr(start_pos, end_pos - start_pos);
            start_pos = end_pos;
            result.push_back(s);
            i = end_pos +pattern.size()- 1;
            // i = pos  - 1;
        }
    }
    return result;
}
std::vector<YAML::Node> convert_str_to_yaml_vector(std::string *data)
{
    std::string pattern = "PROTOCOLTYPE";
    std::vector<std::string> result=split(*data,pattern);

    std::vector<YAML::Node> nodes ;
    YAML::Node temp_node;
    std::cout<<"The result:"<<std::endl;
    for(int i=0; i < (int)(result.size()); i++)
    {
        std::cout<<result[i]<<std::endl;
        nodes.push_back(YAML::Load(result[i].c_str()));
        
    }
    return nodes;
}

void parse_msg_2_msg(void *msg,struct My_MSG * my_msg)
{
    std::vector<YAML::Node> nodes;

    nodes=convert_str_to_yaml_vector((std::string *)msg);

    // for(std::vector<YAML::Node>::iterator iter = nodes.begin(); iter != nodes.end(); ++iter)
    // {
        
    // }
    

    for(int i = nodes.size() -1 ; i>=0 ;i-- )
    {
        
    }
    
}


#endif