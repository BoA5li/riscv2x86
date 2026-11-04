"""Shared finite grammar for GCC/Clang action and dependency output options.

Only dependency-generation forms of -Wp are recognized. Other preprocessor
options, response files and compiler extensions remain explicit prerequisites.
"""


def action_option(args,index):
    arg=args[index]
    pairs={'-o':'output','-MF':'dependency-output','-MT':'dependency-target',
           '-MQ':'dependency-target','-x':'language'}
    if arg in pairs:
        if index+1>=len(args) or not isinstance(args[index+1],str) or not args[index+1]:
            raise ValueError('PROJECT_COMPILE_ARGUMENT_INCOMPLETE:'+arg)
        return pairs[arg],args[index+1],2
    for flag in ('-MF','-MT','-MQ','-o'):
        if arg.startswith(flag) and len(arg)>len(flag):
            return pairs[flag],arg[len(flag):],1
    for flag in ('-Wp,-MMD,','-Wp,-MD,'):
        if arg.startswith(flag):
            value=arg[len(flag):]
            if not value or ',' in value:raise ValueError('PROJECT_DEPENDENCY_OUTPUT_AMBIGUOUS')
            return 'dependency-output',value,1
    return None


def redirect_output(original,value):
    if original[0] in {'-o','-MF'}:return [original[0],str(value)]
    for flag in ('-Wp,-MMD,','-Wp,-MD,'):
        if original[0].startswith(flag):
            if ',' in str(value):raise ValueError('PROJECT_DEPENDENCY_OUTPUT_AMBIGUOUS')
            return [flag+str(value)]
    for flag in ('-MF','-o'):
        if original[0].startswith(flag):return [flag+str(value)]
    raise ValueError('PROJECT_OUTPUT_REDIRECTION_UNSUPPORTED')
