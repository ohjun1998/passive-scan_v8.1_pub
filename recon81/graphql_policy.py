"""Bound selected GraphQL query using the AST, including fragment expansion."""
import json

SIZE={'limit','pagesize','page_size','first','last','count','size','per_page','perpage','length'}


def read_only_graphql(data):
    if not data or len(data)>8192: return False
    try:
        from graphql import parse,OperationType
        from graphql.language import OperationDefinitionNode,FragmentDefinitionNode,FieldNode,FragmentSpreadNode,InlineFragmentNode
        from graphql.utilities import value_from_ast_untyped
        payload=json.loads(data)
        if not isinstance(payload,dict) or not isinstance(payload.get('query'),str): return False
        doc=parse(payload['query'],max_tokens=1000)
        operations=[n for n in doc.definitions if isinstance(n,OperationDefinitionNode)]
        name=payload.get('operationName')
        selected=[n for n in operations if n.name and n.name.value==name] if name else operations
        if len(selected)!=1 or selected[0].operation!=OperationType.QUERY: return False
        operation=selected[0]
        fragments={n.name.value:n for n in doc.definitions if isinstance(n,FragmentDefinitionNode)}
        if len(fragments)>50 or len(fragments)!=sum(isinstance(n,FragmentDefinitionNode) for n in doc.definitions): return False
        variables=payload.get('variables') or {}
        if not isinstance(variables,dict): return False
        def bounded(v,depth=0):
            if depth>10: return False
            if isinstance(v,dict):
                return len(v)<=100 and all((k.lower() not in SIZE or (isinstance(x,int) and not isinstance(x,bool) and 0<=x<=100)) and bounded(x,depth+1) for k,x in v.items())
            if isinstance(v,list): return len(v)<=100 and all(bounded(x,depth+1) for x in v)
            return not isinstance(v,str) or len(v)<=2048
        if not bounded(variables): return False
        variables=dict(variables)
        for definition in operation.variable_definitions or ():
            key=definition.variable.name.value
            if key not in variables and definition.default_value is not None: variables[key]=value_from_ast_untyped(definition.default_value)
        counts={'fields':0,'aliases':0}
        def inspect_set(selection,depth=0,stack=()):
            if depth>10: return False
            for node in selection.selections:
                if isinstance(node,FieldNode):
                    counts['fields']+=1; counts['aliases']+=bool(node.alias)
                    if counts['fields']>100 or counts['aliases']>30 or node.name.value in ('__schema','__type'): return False
                    for argument in node.arguments:
                        value=value_from_ast_untyped(argument.value,variables)
                        if not bounded(value): return False
                        if argument.name.value.lower() in SIZE and (not isinstance(value,int) or isinstance(value,bool) or not 0<=value<=100): return False
                    if node.selection_set and not inspect_set(node.selection_set,depth+1,stack): return False
                elif isinstance(node,FragmentSpreadNode):
                    key=node.name.value
                    if key in stack or key not in fragments or not inspect_set(fragments[key].selection_set,depth,stack+(key,)): return False
                elif isinstance(node,InlineFragmentNode):
                    if not inspect_set(node.selection_set,depth,stack): return False
                else: return False
            return True
        return inspect_set(operation.selection_set)
    except (ImportError,ValueError,TypeError,AttributeError,RecursionError): return False
    except Exception:
        # Parser errors vary across supported graphql-core versions. No regex fallback.
        return False
