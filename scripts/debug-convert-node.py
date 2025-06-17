#!/usr/bin/env python3

import json
import re

def format_js_code(js_code):
    """Formatear código JavaScript minificado para análisis"""
    # Reemplazar ; con ;\n para separar statements
    formatted = js_code.replace('; ', ';\n')
    
    # Agregar saltos de línea después de console.log
    formatted = re.sub(r'(console\.log\([^)]+\));', r'\1;\n', formatted)
    
    # Agregar saltos de línea después de if, else
    formatted = re.sub(r'(\} else \{)', r'\n\1\n', formatted)
    formatted = re.sub(r'(\} if \()', r'\n\1', formatted)
    
    # Agregar indentación básica
    lines = formatted.split('\n')
    formatted_lines = []
    indent_level = 0
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Reducir indentación antes de }
        if line.startswith('}'):
            indent_level = max(0, indent_level - 1)
            
        formatted_lines.append('  ' * indent_level + line)
        
        # Aumentar indentación después de {
        if line.endswith('{'):
            indent_level += 1
    
    return '\n'.join(formatted_lines)

def main():
    # Leer el workflow
    with open('workflows/Enumeracion___Explotacion.json', 'r', encoding='utf-8') as f:
        workflow = json.load(f)
    
    # Buscar el nodo "Convert to Exploitation Format"
    convert_node = None
    for node in workflow['nodes']:
        if node.get('name') == 'Convert to Exploitation Format':
            convert_node = node
            break
    
    if not convert_node:
        print("No se encontró el nodo 'Convert to Exploitation Format'")
        return
    
    # Extraer y formatear el código JavaScript
    js_code = convert_node['parameters']['jsCode']
    
    print("=== CÓDIGO DEL NODO 'Convert to Exploitation Format' ===\n")
    print(format_js_code(js_code))
    print("\n" + "="*60)
    
    # Analizar si preserva datos de DC
    if 'machine_classification' in js_code and 'dc_analysis' in js_code:
        print("✅ El nodo SÍ preserva datos de DC")
    else:
        print("❌ El nodo NO preserva datos de DC")
    
    if 'exploitation_strategy' in js_code:
        print("✅ El nodo SÍ preserva exploitation_strategy")
    else:
        print("❌ El nodo NO preserva exploitation_strategy")

if __name__ == "__main__":
    main() 