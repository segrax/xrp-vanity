#include "stdafx.hpp"
#include <CL/cl.h>

cl_context context;
cl_command_queue command_queue;
cl_program program;
cl_kernel precomp_kernel;
cl_kernel mult_kernel;

void prepKernel() {

    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_int ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_DEFAULT, 1,
        &device_id, &ret_num_devices);

    // Create an OpenCL context
    cl_context context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &ret);

    // Create a command queue
    cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);

    cl_program program;
    {
        std::ifstream source("secp256k1.cl", std::ios_base::in | std::ios_base::binary | std::ios::ate);
        size_t size = source.tellg();

        std::string KeyContents((std::istreambuf_iterator<char>(source)),
            (std::istreambuf_iterator<char>()));

        const char *sources[] = { KeyContents.c_str() };
        const size_t lens[] = { KeyContents.length() };

        program = clCreateProgramWithSource(context, 1,
            sources, lens, &ret);

        ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
        std::cout << ret << std::endl;

        size_t len;
        char *buffer;
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
        buffer = (char *)malloc(len);
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, len, buffer, NULL);
        std::cout << buffer << std::endl;
    }


    precomp_kernel = clCreateKernel(program, "secp256k1_ecmult_table_precomp_gej", &ret);
    mult_kernel = clCreateKernel(program, "secp256k1_ecmult", &ret);
}
