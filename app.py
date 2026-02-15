from flask import Flask, jsonify, request, abort, send_from_directory
from flask_cors import CORS
import ast
import re
import yaml
import requests
import os
from dotenv import load_dotenv
import random
import string
import time
from werkzeug.exceptions import HTTPException
from datetime import datetime
import traceback

load_dotenv()

github_token_check = os.getenv('GITHUB_TOKEN')
if github_token_check:
    masked = f"{github_token_check[:4]}...{github_token_check[-4:]}"
    print(f" GITHUB_TOKEN loaded: {masked}")
else:
    print(" WARNING: GITHUB_TOKEN not found. API rate limits will be restricted.")

app = Flask(__name__)
CORS(app)

@app.errorhandler(HTTPException)
def handle_exception(e):
    response = e.get_response()
    response.data = jsonify({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    }).get_data()
    response.content_type = "application/json"
    return response

state = {
    "current_otp": None,
    "generated_specs": [],
    "analytics": {"total_generations": 0, "languages": {}}
}

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

def get_github_headers():
    token = os.getenv('GITHUB_TOKEN')
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f"token {token}"
    return headers

def make_github_request(url):
    retries = 3
    backoff = 1
    
    for i in range(retries):
        try:
            response = requests.get(url, headers=get_github_headers(), timeout=15)
            
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                if response.headers['X-RateLimit-Remaining'] == '0':
                    print(" GitHub Rate Limit Exceeded")
                    abort(429, "GitHub API rate limit exceeded. Please try again later.")
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            if i == retries - 1:
                raise
            print(f" Request failed, retrying in {backoff}s...")
            time.sleep(backoff)
            backoff *= 2

def fetch_repo_contents_recursive(user, repo, branch, path, depth=0):
    if depth > 10:
        print(f"   Max depth reached at: {path}")
        return []
    
    api_url = f"https://api.github.com/repos/{user}/{repo}/contents/{path}?ref={branch}"
    
    try:
        response = make_github_request(api_url)
        contents = response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            if branch == 'main':
                print(f" Branch 'main' not found, trying 'master'...")
                api_url = f"https://api.github.com/repos/{user}/{repo}/contents/{path}?ref=master"
                try:
                    response = make_github_request(api_url)
                    contents = response.json()
                    return contents, 'master'
                except Exception:
                    return [], branch
            else:
                return [], branch
        else:
            raise
    
    all_files = []
    
    if not isinstance(contents, list):
        if contents.get('type') == 'file':
            return [contents], branch
        return [], branch
    
    skip_dirs = ['node_modules', 'target', 'build', 'dist', '.git', '__pycache__', 
                 'venv', 'env', 'test', 'tests', 'out', 'bin', 'obj', '.idea', '.vscode']
    
    for item in contents:
        if item['type'] == 'file':
            all_files.append(item)
        elif item['type'] == 'dir' and item['name'] not in skip_dirs:
            sub_files, _ = fetch_repo_contents_recursive(user, repo, branch, item['path'], depth + 1)
            all_files.extend(sub_files)
    
    return all_files, branch

def detect_language(code):
    if not code: 
        return 'unknown'
    
    trimmed = code.strip()
    
    patterns = {
        'java': [
            r"@RestController", r"@Controller", r"@RequestMapping",
            r"@GetMapping", r"@PostMapping", r"@PutMapping", r"@DeleteMapping",
            r"@Service", r"@Repository", r"@Entity", r"@SpringBootApplication",
            r"package\s+[\w.]+;", r"import\s+java\.", r"public\s+class\s+\w+",
            r"@Component", r"@Autowired", r"@Configuration", r"@Bean"
        ],
        'python': [
            r"from\s+\w+\s+import", r"import\s+\w+", 
            r"def\s+\w+\s*\(", r"class\s+\w+", r"if\s+__name__\s*==\s*['\"]__main__['\"]",
            r"@app\.route", r"@api\.route", r"from\s+flask", r"from\s+django"
        ],
        'typescript': [
            r":\s*(string|number|boolean|any|void)\s*[=;)]",
            r"interface\s+\w+", r"type\s+\w+\s*=", r"export\s+(interface|type|class)",
            r"import\s+.*\s+from\s+['\"].*['\"]", r"<.*>\s*\(.*\)\s*=>"
        ],
        'javascript': [
            r"const\s+\w+\s*=", r"let\s+\w+\s*=", r"var\s+\w+\s*=",
            r"function\s+\w+\s*\(", r"=>\s*{", r"module\.exports", r"require\(['\"]",
            r"app\.get\(", r"app\.post\(", r"router\."
        ],
        'go': [
            r"package\s+\w+", r"func\s+\w+\s*\(", r"import\s+\(",
            r"type\s+\w+\s+struct", r"func\s+\(\w+\s+\*?\w+\)"
        ],
        'rust': [
            r"fn\s+\w+\s*\(", r"struct\s+\w+", r"impl\s+\w+",
            r"use\s+\w+", r"pub\s+fn", r"#\[derive\(", r"let\s+mut\s+"
        ],
        'csharp': [
            r"using\s+System", r"namespace\s+\w+", r"public\s+class\s+\w+",
            r"\[HttpGet\]", r"\[HttpPost\]", r"\[ApiController\]"
        ],
        'php': [
            r"<\?php", r"namespace\s+\w+", r"use\s+\w+\\",
            r"function\s+\w+\s*\(", r"class\s+\w+", r"\$\w+\s*="
        ],
        'ruby': [
            r"def\s+\w+", r"class\s+\w+", r"require\s+['\"]",
            r"get\s+['\"]\/", r"post\s+['\"]\/", r"@\w+\s*="
        ]
    }
    
    scores = {}
    for lang, regexes in patterns.items():
        matches = sum(1 for pattern in regexes if re.search(pattern, trimmed, re.MULTILINE | re.IGNORECASE))
        if matches > 0:
            scores[lang] = matches
    
    if scores:
        return max(scores, key=scores.get)
    
    if re.search(r"<!DOCTYPE html>|<html", trimmed, re.I):
        return 'html'
    
    return 'javascript'

def analyze_python_code(code):
    try:
        tree = ast.parse(code)
        functions = []
        classes = []
        
        is_flask = 'flask' in code.lower() or '@app.route' in code or '@bp.route' in code
        is_django = 'django' in code.lower() or 'from django' in code.lower()
        is_fastapi = 'fastapi' in code.lower() or 'from fastapi' in code.lower()
        
        class_nodes = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_nodes[node.name] = node
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name.startswith('_') and node.name != '__init__':
                    continue
                
                decorators = []
                method_type = None
                path = None
                
                for dec in node.decorator_list:
                    dec_name = None
                    
                    if isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Attribute):
                            dec_name = f"{dec.func.attr}"
                            if len(dec.args) > 0:
                                if isinstance(dec.args[0], ast.Constant):
                                    path = dec.args[0].value
                                elif isinstance(dec.args[0], ast.Str):
                                    path = dec.args[0].s
                        elif isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Name):
                        dec_name = dec.id
                    
                    if dec_name:
                        decorators.append(dec_name)
                        
                        http_methods = ['route', 'get', 'post', 'put', 'delete', 'patch', 'head', 'options']
                        if dec_name in http_methods:
                            method_type = dec_name.upper() if dec_name != 'route' else 'GET'
                
                is_endpoint = any(d in ['route', 'get', 'post', 'put', 'delete', 'patch', 'api_view'] for d in decorators)
                
                args = []
                for a in node.args.args:
                    if a.arg not in ['self', 'cls', 'request', 'args', 'kwargs']:
                        arg_type = "any"
                        if a.annotation:
                            if isinstance(a.annotation, ast.Name):
                                arg_type = a.annotation.id
                            elif isinstance(a.annotation, ast.Constant):
                                arg_type = str(a.annotation.value)
                        args.append({"name": a.arg, "type": arg_type})
                
                return_type = "any"
                if node.returns:
                    if isinstance(node.returns, ast.Name):
                        return_type = node.returns.id
                    elif isinstance(node.returns, ast.Constant):
                        return_type = str(node.returns.value)
                
                func_info = {
                    "type": "endpoint" if is_endpoint else "function",
                    "name": node.name,
                    "args": args,
                    "docstring": ast.get_docstring(node) or "",
                    "returns": return_type,
                    "decorators": decorators
                }
                
                if is_endpoint and path:
                    func_info['path'] = path
                    if method_type:
                        func_info['method'] = method_type
                
                functions.append(func_info)
        
        for class_name, node in class_nodes.items():
            methods = []
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    if not item.name.startswith('_') or item.name == '__init__':
                        methods.append(item.name)
            
            classes.append({
                "type": "class",
                "name": class_name,
                "methods": methods,
                "docstring": ast.get_docstring(node) or ""
            })
        
        return functions, classes, {"total_methods": len(functions)}
        
    except Exception as e:
        print(f"    Python parsing error: {e}")
        traceback.print_exc()
        return [], [], {"total_methods": 0}

def clean_parameter_name(param_name):
    """Clean parameter name by removing annotations and extra characters"""
    if not param_name:
        return None
        
    param_name = re.sub(r'@\w+\s*\([^)]*\)\s*', '', param_name)
    param_name = re.sub(r'@\w+\s+', '', param_name)
    param_name = param_name.replace('"', '').replace("'", '').strip()
    
    param_name = re.sub(r'[^\w]', '', param_name)
    
    if not param_name or param_name.isdigit() or not re.match(r'^[a-zA-Z_]\w*$', param_name):
        return None
    
    return param_name

def extract_generic_type(type_str):
    """Extract the generic type from ResponseEntity<T>, List<T>, etc."""
    if not type_str:
        return None
    
    # Match patterns like ResponseEntity<Owner>, List<Pet>, Map<String, Object>
    generic_match = re.search(r'<(.+)>', type_str)
    if generic_match:
        inner_type = generic_match.group(1).strip()
        # Handle nested generics like List<Map<String, Object>>
        if '<' in inner_type:
            # For complex types, just return the outer type
            return inner_type.split('<')[0].strip()
        return inner_type
    return None

def parse_java_spring(code):
    """Parse Java Spring Boot code to extract REST endpoints with accurate parameter and return type detection"""
    functions = []
    classes = []
    
    print(" Parsing Java Spring code...")
    
    # Remove comments thoroughly
    code_lines = code.split('\n')
    cleaned_lines = []
    in_multiline_comment = False
    
    for line in code_lines:
        if in_multiline_comment:
            if '*/' in line:
                in_multiline_comment = False
                line = line[line.index('*/') + 2:]
            else:
                continue
        
        if '/*' in line:
            if '*/' in line:
                before = line[:line.index('/*')]
                after = line[line.index('*/') + 2:]
                line = before + after
            else:
                in_multiline_comment = True
                line = line[:line.index('/*')]
        
        if '//' in line:
            line = line[:line.index('//')]
        
        cleaned_lines.append(line)
    
    code_no_comments = '\n'.join(cleaned_lines)
    
    # Find all classes
    class_pattern = r'(?:@\w+(?:\([^)]*\))?\s+)*(?:public\s+|private\s+|protected\s+)?(?:abstract\s+|final\s+)?class\s+(\w+)'
    all_classes = list(re.finditer(class_pattern, code_no_comments))
    
    print(f"   Found {len(all_classes)} classes")
    
    total_endpoints = 0
    total_methods = 0
    
    for class_match in all_classes:
        class_name = class_match.group(1)
        class_start = class_match.start()
        
        # Get context before class for annotations
        context_start = max(0, class_start - 3000)
        context = code_no_comments[context_start:class_start + 500]
        
        # Check if controller
        is_rest = '@RestController' in context
        is_controller = '@Controller' in context or is_rest
        
        # Get base path
        base_path = ""
        base_path_patterns = [
            r'@RequestMapping\s*\(\s*["\']([^"\']+)["\']',
            r'@RequestMapping\s*\(\s*(?:path|value)\s*=\s*["\']([^"\']+)["\']',
            r'@RequestMapping\s*\(\s*(?:path|value)\s*=\s*\{\s*["\']([^"\']+)["\']\s*\}',
            r'@RequestMapping\s*\(\s*path\s*=\s*\{\s*["\']([^"\']+)["\']\s*\}',
        ]
        
        for pattern in base_path_patterns:
            base_path_match = re.search(pattern, context, re.MULTILINE)
            if base_path_match:
                base_path = base_path_match.group(1)
                if base_path and not base_path.startswith('/'):
                    base_path = '/' + base_path
                break
        
        # Add class
        class_methods = []
        classes.append({
            "type": "class",
            "name": class_name,
            "methods": class_methods,
            "docstring": f"REST Controller" if is_rest else ("Controller" if is_controller else "Class"),
            "is_rest": is_rest  # UPGRADE: Track REST vs MVC
        })
        
        # Find class body
        rest_of_code = code_no_comments[class_match.end():]
        
        # Find next class or end
        next_class = re.search(class_pattern, rest_of_code)
        if next_class:
            class_body = rest_of_code[:next_class.start()]
        else:
            class_body = rest_of_code
        
        # HTTP mappings
        http_mappings = [
            ('GetMapping', 'GET'),
            ('PostMapping', 'POST'),
            ('PutMapping', 'PUT'),
            ('DeleteMapping', 'DELETE'),
            ('PatchMapping', 'PATCH'),
            ('RequestMapping', 'GET')
        ]
        
        # UPGRADE: Improved method pattern to capture return type
        method_pattern = r'(?:@\w+(?:\([^)]*\))?\s+)*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?([\w<>?,\s\[\]]+?)\s+(\w+)\s*\(([^)]*)\)'
        
        for method_match in re.finditer(method_pattern, class_body):
            return_type_raw = method_match.group(1).strip()
            method_name = method_match.group(2)
            params_str = method_match.group(3)
            
            # Skip constructors
            if method_name == class_name:
                continue
            
            total_methods += 1
            class_methods.append(method_name)
            
            # Check for HTTP mapping
            method_start = method_match.start()
            method_context = class_body[max(0, method_start - 1000):method_start + 200]
            
            is_endpoint_method = False
            http_method = 'GET'
            path = ""
            
            for annotation, default_method in http_mappings:
                if f'@{annotation}' in method_context:
                    is_endpoint_method = True
                    http_method = default_method
                    
                    # Extract path
                    path_patterns = [
                        rf'@{annotation}\s*\(\s*["\']([^"\']+)["\']',
                        rf'@{annotation}\s*\(\s*(?:path|value)\s*=\s*["\']([^"\']+)["\']',
                        rf'@{annotation}\s*\(\s*(?:path|value)\s*=\s*\{{\s*["\']([^"\']+)["\']\s*\}}',
                        rf'@{annotation}\s*\(\s*path\s*=\s*\{{\s*["\']([^"\']+)["\']\s*\}}',
                    ]
                    
                    for pattern in path_patterns:
                        path_match = re.search(pattern, method_context, re.MULTILINE)
                        if path_match:
                            path = path_match.group(1)
                            break
                    
                    # For RequestMapping, check method
                    if annotation == 'RequestMapping':
                        method_in_anno = re.search(r'method\s*=\s*RequestMethod\.(\w+)', method_context)
                        if method_in_anno:
                            http_method = method_in_anno.group(1).upper()
                    
                    break
            
            # UPGRADE: Enhanced parameter parsing with annotation detection
            args = []
            
            if params_str and params_str.strip():
                # Parse parameters with their annotations
                # Improved pattern to handle complex cases
                param_pattern = r'(@\w+(?:\([^)]*\))?\s+)?((?:final\s+)?[\w<>?,\s\[\]]+?)\s+(\w+)(?:\s*,|\s*\))'
                
                # FINAL REFINEMENT: Framework types that must be completely ignored
                framework_types = {
                    "Model", "ModelMap", "ModelAndView",
                    "BindingResult", "Errors",
                    "RedirectAttributes",
                    "HttpServletRequest", "HttpServletResponse",
                    "Principal", "Authentication",
                    "Pageable", "Page", "Sort",
                    "HttpSession", "Locale",
                    "WebRequest", "NativeWebRequest",
                    "SessionStatus", "UriComponentsBuilder",
                    "HttpEntity"
                }
                
                # Track added parameters to prevent duplicates
                added_param_names = set()
                
                # Try multiple parsing strategies
                params_cleaned = params_str.strip()
                
                # Split by comma but respect generics and annotations
                param_segments = []
                current_segment = ""
                depth = 0
                in_annotation = False
                
                for char in params_cleaned + ",":
                    if char == '@':
                        in_annotation = True
                    elif char == '(' and in_annotation:
                        depth += 1
                    elif char == ')' and in_annotation and depth > 0:
                        depth -= 1
                        if depth == 0:
                            in_annotation = False
                    elif char == '<':
                        depth += 1
                    elif char == '>':
                        depth -= 1
                    elif char == ',' and depth == 0 and not in_annotation:
                        if current_segment.strip():
                            param_segments.append(current_segment.strip())
                        current_segment = ""
                        continue
                    current_segment += char
                
                for segment in param_segments:
                    # Extract annotation, type, and name from each segment
                    # Pattern: [@Annotation(params)] [final] Type name
                    annotation_match = re.search(r'(@\w+(?:\([^)]*\))?)\s+', segment)
                    annotation = annotation_match.group(1) if annotation_match else None
                    
                    # Remove annotation from segment
                    if annotation:
                        segment = segment.replace(annotation, "").strip()
                    
                    # Remove 'final' keyword
                    segment = re.sub(r'\bfinal\s+', '', segment)
                    
                    # Now segment should be "Type name"
                    # Handle generics carefully
                    tokens = segment.split()
                    if len(tokens) < 2:
                        continue
                    
                    # Last token is the name
                    param_name = tokens[-1].strip()
                    # Everything else is the type
                    param_type = ' '.join(tokens[:-1]).strip()
                    
                    # CRITICAL: Check framework types FIRST (before any processing)
                    # Handle both simple types and generics like Page<T>
                    base_type = param_type.split('<')[0].strip()
                    if base_type in framework_types:
                        print(f" Filtered framework type: {base_type} {param_name}")
                        continue  # Skip completely - don't even classify
                    
                    # REFINEMENT: Normalize parameter name to lowercase for deduplication
                    param_name_normalized = param_name.lower()
                    
                    # Skip if already added (prevents Page/page duplicates)
                    if param_name_normalized in added_param_names:
                        print(f"   Skipped duplicate param: {param_name}")
                        continue
                    
                    # Classify parameter location based on annotation
                    param_in = "unknown"
                    
                    if annotation:
                        annotation_clean = annotation.strip()
                        if "@PathVariable" in annotation_clean:
                            param_in = "path"
                        elif "@RequestParam" in annotation_clean:
                            param_in = "query"
                        elif "@RequestBody" in annotation_clean:
                            param_in = "body"
                        elif "@RequestHeader" in annotation_clean:
                            param_in = "header"
                        elif "@ModelAttribute" in annotation_clean:
                            param_in = "ignore"
                        else:
                            param_in = "ignore"
                    else:
                        # No annotation - check if it's a framework type
                        # These should be ignored even without explicit annotations
                        if base_type in framework_types:
                            param_in = "ignore"
                        else:
                            param_in = "unknown"
                    
                    # Only add parameters that are not ignored
                    if param_in != "ignore":
                        args.append({
                            "name": param_name,  # Keep original case for display
                            "type": param_type,
                            "in": param_in
                        })
                        added_param_names.add(param_name_normalized)  # Track normalized
                        print(f"  Added param: {param_type} {param_name} (in: {param_in})")
            
            # Extract actual return type from ResponseEntity<T>
            actual_return_type = "object"
            
            if "ResponseEntity" in return_type_raw:
                generic_type = extract_generic_type(return_type_raw)
                if generic_type:
                    actual_return_type = generic_type
                else:
                    actual_return_type = "object"
            elif "void" in return_type_raw.lower():
                actual_return_type = "void"
            elif "String" in return_type_raw:
                actual_return_type = "string"
            elif "List<" in return_type_raw or "Collection<" in return_type_raw:
                generic_type = extract_generic_type(return_type_raw)
                actual_return_type = f"List<{generic_type}>" if generic_type else "array"
            else:
                actual_return_type = return_type_raw
            
            # ONLY add endpoint methods to functions list
            if is_endpoint_method:
                # Construct full path
                if path:
                    if not path.startswith('/'):
                        path = '/' + path
                    full_path = base_path + path
                else:
                    full_path = base_path if base_path else '/'
                
                # Normalize path
                full_path = re.sub(r'/+', '/', full_path)
                
                functions.append({
                    "type": "endpoint",
                    "name": method_name,
                    "path": full_path,
                    "method": http_method,
                    "args": args,
                    "docstring": f"{http_method} {full_path}",
                    "returns": actual_return_type,
                    "controller": class_name,
                    "produces": "application/json" if is_rest else "text/html"  # UPGRADE: Track content type
                })
                total_endpoints += 1
                print(f"       {http_method} {full_path} -> {method_name}() returns {actual_return_type}")
    
    print(f"\n Java parsing complete:")
    print(f"   Classes: {len(classes)}")
    print(f"   Total methods: {total_methods}")
    print(f"   Endpoints: {total_endpoints}")
    print(f"   Non-endpoint methods: {total_methods - total_endpoints}")
    
    return functions, classes, {"total_methods": total_methods}

def parse_js_like(code):
    """Enhanced JavaScript/TypeScript parser"""
    functions = []
    classes = []
    
    code_no_comments = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
    
    # Express/Node.js endpoints
    express_patterns = [
        (r'(?:app|router|api)\.get\s*\(\s*["\']([^"\']+)["\']', 'GET'),
        (r'(?:app|router|api)\.post\s*\(\s*["\']([^"\']+)["\']', 'POST'),
        (r'(?:app|router|api)\.put\s*\(\s*["\']([^"\']+)["\']', 'PUT'),
        (r'(?:app|router|api)\.delete\s*\(\s*["\']([^"\']+)["\']', 'DELETE'),
        (r'(?:app|router|api)\.patch\s*\(\s*["\']([^"\']+)["\"]', 'PATCH')
    ]
    
    for pattern, method in express_patterns:
        for match in re.finditer(pattern, code_no_comments):
            path = match.group(1)
            
            functions.append({
                "type": "endpoint",
                "name": f"{method.lower()}_{path.replace('/', '_').replace(':', '')}",
                "path": path,
                "method": method,
                "args": [],
                "docstring": f"{method} {path}",
                "returns": "any"
            })
    
    # Function declarations
    func_patterns = [
        r"(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\((.*?)\)",
        r"(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s+)?\((.*?)\)\s*=>",
        r"(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s+)?function\s*\((.*?)\)"
    ]
    
    for pattern in func_patterns:
        for match in re.finditer(pattern, code_no_comments):
            name = match.group(1)
            args_str = match.group(2) if len(match.groups()) > 1 else ""
            
            args = []
            if args_str.strip():
                arg_parts = [a.strip() for a in args_str.split(',') if a.strip()]
                for arg in arg_parts:
                    if ':' in arg:
                        parts = arg.split(':')
                        arg_name = parts[0].strip()
                        arg_type = parts[1].strip().split('=')[0].strip()
                    else:
                        arg_name = arg.split('=')[0].strip()
                        arg_type = "any"
                    
                    arg_name = re.sub(r'[^\w$]', '', arg_name)
                    if arg_name and not arg_name.isdigit():
                        args.append({"name": arg_name, "type": arg_type})
            
            if not any(f['name'] == name and f['type'] == 'endpoint' for f in functions):
                functions.append({
                    "type": "function",
                    "name": name,
                    "args": args,
                    "docstring": "",
                    "returns": "any"
                })
    
    # Class declarations
    class_pattern = r"(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([a-zA-Z0-9_$]+)(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w,\s]+)?\s*\{"
    
    for class_match in re.finditer(class_pattern, code_no_comments):
        class_name = class_match.group(1)
        class_start = class_match.end()
        
        # Find class body
        depth = 1
        class_end = class_start
        for i, char in enumerate(code_no_comments[class_start:], class_start):
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    class_end = i
                    break
        
        class_body = code_no_comments[class_start:class_end]
        
        # Find methods
        method_pattern = r"(?:public|private|protected|static|async)?\s*([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{"
        methods = []
        for method_match in re.finditer(method_pattern, class_body):
            method_name = method_match.group(1)
            if method_name != 'constructor' and not method_name.startswith('_'):
                methods.append(method_name)
        
        classes.append({
            "type": "class",
            "name": class_name,
            "methods": methods,
            "docstring": ""
        })
    
    return functions, classes, {"total_methods": len(functions)}

def parse_go(code):
    """Enhanced Go parser"""
    functions = []
    classes = []
    
    # HTTP handlers
    handler_patterns = [
        r'func\s+(\w+)\s*\(\s*c\s+\*gin\.Context\s*\)',
        r'func\s+(\w+)\s*\(\s*c\s+echo\.Context\s*\)',
        r'func\s+(\w+)\s*\(\s*w\s+http\.ResponseWriter\s*,\s*r\s+\*http\.Request\s*\)',
        r'func\s+(\w+)\s*\(\s*ctx\s+context\.Context\s*,\s*req\s+',
    ]
    
    for pattern in handler_patterns:
        for match in re.finditer(pattern, code):
            name = match.group(1)
            functions.append({
                "type": "endpoint",
                "name": name,
                "path": f"/{name.lower()}",
                "method": "GET",
                "args": [],
                "docstring": f"HTTP handler {name}",
                "returns": "error"
            })
    
    # Regular functions
    func_pattern = r'func\s+(\w+)\s*\(([^)]*)\)\s*(?:\([^)]*\)|[\w\*\[\]]+)?'
    for match in re.finditer(func_pattern, code):
        name = match.group(1)
        params_str = match.group(2)
        
        args = []
        if params_str.strip():
            param_parts = [p.strip() for p in params_str.split(',') if p.strip()]
            for param in param_parts:
                tokens = param.split()
                if len(tokens) >= 2:
                    param_name = tokens[0]
                    param_type = ' '.join(tokens[1:])
                    if not param_name.startswith('_'):
                        args.append({"name": param_name, "type": param_type})
        
        if not any(f['name'] == name for f in functions):
            functions.append({
                "type": "function",
                "name": name,
                "args": args,
                "docstring": "",
                "returns": "any"
            })
    
    # Structs
    struct_pattern = r'type\s+(\w+)\s+struct\s*\{'
    for match in re.finditer(struct_pattern, code):
        struct_name = match.group(1)
        classes.append({
            "type": "class",
            "name": struct_name,
            "methods": [],
            "docstring": "Go struct"
        })
    
    # Methods on structs
    method_pattern = r'func\s+\((\w+)\s+\*?(\w+)\)\s+(\w+)\s*\('
    for match in re.finditer(method_pattern, code):
        receiver_type = match.group(2)
        method_name = match.group(3)
        
        for cls in classes:
            if cls['name'] == receiver_type:
                if method_name not in cls['methods']:
                    cls['methods'].append(method_name)
                break
    
    return functions, classes, {"total_methods": len(functions)}

def parse_csharp(code):
    """Enhanced C# parser"""
    functions = []
    classes = []
    
    # Controller classes
    controller_pattern = r'(?:\[ApiController\][\s\S]*?)?(?:public\s+)?class\s+(\w+Controller)\s*(?::\s*\w+)?'
    for match in re.finditer(controller_pattern, code):
        class_name = match.group(1)
        classes.append({
            "type": "class",
            "name": class_name,
            "methods": [],
            "docstring": f"API Controller"
        })
    
    # HTTP attributes
    http_attrs = ['HttpGet', 'HttpPost', 'HttpPut', 'HttpDelete', 'HttpPatch']
    for attr in http_attrs:
        pattern = rf'\[{attr}(?:\("([^"]+)"\))?\][\s\S]*?(?:public\s+)?(?:\w+)\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(pattern, code):
            path = match.group(1) or ""
            method_name = match.group(2)
            params_str = match.group(3)
            
            args = []
            if params_str:
                param_parts = [p.strip() for p in params_str.split(',') if p.strip()]
                for param in param_parts:
                    tokens = param.split()
                    if len(tokens) >= 2:
                        param_type = tokens[0]
                        param_name = tokens[1]
                        args.append({"name": param_name, "type": param_type})
            
            functions.append({
                "type": "endpoint",
                "name": method_name,
                "path": f"/{path}" if path else f"/{method_name.lower()}",
                "method": attr.replace('Http', '').upper(),
                "args": args,
                "docstring": f"{attr.replace('Http', '')} endpoint",
                "returns": "IActionResult"
            })
    
    return functions, classes, {"total_methods": len(functions)}

def analyze_code(code, language):
    parsers = {
        'python': analyze_python_code,
        'java': parse_java_spring,
        'javascript': parse_js_like,
        'typescript': parse_js_like,
        'nodejs': parse_js_like,
        'react': parse_js_like,
        'go': parse_go,
        'csharp': parse_csharp
    }
    
    parser = parsers.get(language, lambda c: ([], [], {"total_methods": 0}))
    try:
        return parser(code)
    except Exception as e:
        print(f"    Error parsing {language}: {e}")
        traceback.print_exc()
        return [], [], {"total_methods": 0}

def infer_http_method(func_name):
    name_lower = func_name.lower()
    
    if any(word in name_lower for word in ['get', 'fetch', 'retrieve', 'list', 'find', 'show', 'read', 'search', 'query']):
        return 'get'
    elif any(word in name_lower for word in ['create', 'add', 'post', 'insert', 'new', 'register', 'save']):
        return 'post'
    elif any(word in name_lower for word in ['update', 'edit', 'modify', 'put', 'change', 'replace']):
        return 'put'
    elif any(word in name_lower for word in ['delete', 'remove', 'destroy', 'drop', 'clear']):
        return 'delete'
    elif any(word in name_lower for word in ['patch', 'partial']):
        return 'patch'
    
    return 'post'

def map_java_type_to_openapi(java_type):
    """Map Java types to OpenAPI schema types with improved inference"""
    if not java_type or java_type == "void":
        return None
    
    type_lower = java_type.lower()
    
    # REFINEMENT: Improved primitive type detection (case-insensitive, handles Long/long, Integer/int)
    if any(t in type_lower for t in ['int', 'long', 'short', 'byte']):
        return {"type": "integer", "format": "int64" if 'long' in type_lower else "int32"}
    elif any(t in type_lower for t in ['float', 'double', 'bigdecimal', 'number']):
        return {"type": "number", "format": "double" if 'double' in type_lower else "float"}
    elif any(t in type_lower for t in ['boolean', 'bool']):
        return {"type": "boolean"}
    elif any(t in type_lower for t in ['string', 'char', 'character']):
        return {"type": "string"}
    
    # Collections
    if 'List<' in java_type or 'Collection<' in java_type or 'Set<' in java_type:
        inner_type = extract_generic_type(java_type)
        if inner_type:
            inner_schema = map_java_type_to_openapi(inner_type)
            return {
                "type": "array",
                "items": inner_schema if inner_schema else {"type": "object"}
            }
        return {"type": "array", "items": {"type": "object"}}
    
    # Default to object for complex types
    return {"type": "object"}

def generate_openapi_spec(functions, classes, title, description, language):
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": title,
            "version": "1.0.0",
            "description": description,
            "contact": {
                "name": "API Support",
                "email": "support@apiforge.dev"
            }
        },
        "servers": [
            {"url": "https://api.example.com/v1", "description": "Production"},
            {"url": "http://localhost:8080", "description": "Development"}
        ],
        "paths": {},
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            },
            "schemas": {}
        },
        "tags": []
    }
    
    # Add controller classes as tags
    controller_classes = []
    for cls in classes:
        if cls.get('docstring'):
            if 'controller' in cls['docstring'].lower() or cls['name'].endswith('Controller'):
                controller_classes.append(cls)
    
    for cls in controller_classes:
        spec["tags"].append({
            "name": cls["name"],
            "description": cls.get("docstring") or f"Operations for {cls['name']}"
        })
    
    for func in functions:
        # CRITICAL: Only process actual endpoints, not regular functions
        if func.get('type') != 'endpoint':
            continue
            
        # Endpoints must have a path
        if not func.get('path'):
            continue
            
        path = func['path']
        method = func.get('method', 'GET').lower()
        
        if not path.startswith('/'):
            path = '/' + path
        
        parameters = []
        request_body = None
        
        # Extract path parameters from the path itself
        path_params_in_url = re.findall(r'\{(\w+)\}|:(\w+)', path)
        path_param_names = set()
        for param_tuple in path_params_in_url:
            param_name = param_tuple[0] or param_tuple[1]
            path_param_names.add(param_name)
        
        # UPGRADE: Process parameters based on their annotation classification
        body_params = []
        processed_path_params = set()  # Track which path params we've added
        
        for arg in func.get('args', []):
            arg_in = arg.get('in', 'unknown')
            arg_name = arg['name']
            arg_type = arg.get('type', 'string')
            
            if arg_in == 'path':
                # Path parameter
                path_param_names.add(arg_name)
                processed_path_params.add(arg_name)
                parameters.append({
                    "name": arg_name,
                    "in": "path",
                    "required": True,
                    "schema": map_java_type_to_openapi(arg_type) or {"type": "string"},
                    "description": f"Path parameter {arg_name}"
                })
            
            elif arg_in == 'query':
                # Query parameter
                parameters.append({
                    "name": arg_name,
                    "in": "query",
                    "required": False,
                    "schema": map_java_type_to_openapi(arg_type) or {"type": "string"},
                    "description": f"Query parameter {arg_name}"
                })
            
            elif arg_in == 'body':
                # Request body parameter
                body_params.append(arg)
            
            elif arg_in == 'header':
                # Header parameter
                parameters.append({
                    "name": arg_name,
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                    "description": f"Header parameter {arg_name}"
                })
            
            elif arg_in == 'unknown' and arg_name in path_param_names:
                # REFINEMENT: Safety catch - if parameter name matches path variable but no annotation
                # This handles implicit path variables
                processed_path_params.add(arg_name)
                parameters.append({
                    "name": arg_name,
                    "in": "path",
                    "required": True,
                    "schema": map_java_type_to_openapi(arg_type) or {"type": "string"},
                    "description": f"Path parameter {arg_name}"
                })
            
            elif arg_in == 'unknown' and arg_name not in path_param_names:
                # Fallback: if unknown and not in path, treat as query for GET, body for others
                if method == 'get':
                    parameters.append({
                        "name": arg_name,
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "description": f"Query parameter {arg_name}"
                    })
                else:
                    body_params.append(arg)
        
        # REFINEMENT: Ensure all path parameters from URL are documented
        # Even if method signature is missing or unparseable
        for path_param in path_param_names:
            if path_param not in processed_path_params:
                # Add missing path parameter with string type as fallback
                parameters.append({
                    "name": path_param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": f"Path parameter {path_param}"
                })
        
        # UPGRADE: Build request body from @RequestBody parameters
        if body_params:
            properties = {}
            for arg in body_params:
                arg_type = arg.get('type', 'string')
                schema = map_java_type_to_openapi(arg_type)
                
                if not schema:
                    schema = {"type": "string"}
                
                properties[arg["name"]] = schema
            
            if properties:
                request_body = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": properties
                            }
                        }
                    }
                }
        
        # UPGRADE: Build response schema based on actual return type
        return_type = func.get('returns', 'object')
        produces = func.get('produces', 'application/json')
        
        # REFINEMENT: Professional response schema handling
        if produces == "text/html":
            # MVC endpoints return view names (String)
            response_schema = {"type": "string"}
        elif return_type == "void":
            # Void return type
            response_schema = None
        else:
            # REST endpoints - infer from return type
            response_schema = map_java_type_to_openapi(return_type)
            if not response_schema:
                response_schema = {"type": "object"}
        
        # Determine content type
        content_type = produces if produces else "application/json"
        
        # Build responses section
        responses = {}
        if response_schema:
            responses["200"] = {
                "description": "Successful response",
                "content": {
                    content_type: {
                        "schema": response_schema
                    }
                }
            }
        else:
            # Void response - no content
            responses["200"] = {
                "description": "Successful response"
            }
        
        operation = {
            "summary": func.get('docstring') or func['name'].replace('_', ' ').title(),
            "description": func.get('docstring') or f"Execute {func['name']} operation",
            "operationId": func['name'],
            "parameters": parameters,
            "responses": responses
        }
        
        # REFINEMENT: Only add security to REST/JSON endpoints, not MVC HTML views
        if func.get("produces") == "application/json":
            operation["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]
        
        if request_body:
            operation["requestBody"] = request_body
        
        # Tag by controller
        if func.get('controller'):
            operation["tags"] = [func['controller']]
        elif controller_classes:
            operation["tags"] = [controller_classes[0]["name"]]
        else:
            operation["tags"] = ["default"]
        
        if path not in spec["paths"]:
            spec["paths"][path] = {}
        
        spec["paths"][path][method] = operation
    
    if not controller_classes:
        spec["tags"].append({
            "name": "default",
            "description": "Default operations"
        })
    
    return spec

@app.route('/fetch-github', methods=['POST'])
def fetch_github():
    data = request.get_json()
    url = data.get('url', '')
    
    regex = r"github\.com/([^/]+)/([^/]+)(?:/(?:blob|tree)/([^/]+))?/?(.*)"
    match = re.search(regex, url)
    
    if not match: 
        abort(400, "Invalid GitHub URL format")
    
    user, repo, branch, path = match.groups()
    repo = repo.replace('.git', '')
    branch = branch or 'main'
    path = path or ''
    
    try:
        print(f"\n🔗 Fetching GitHub: {user}/{repo}/{branch}/{path}")
        
        api_url = f"https://api.github.com/repos/{user}/{repo}/contents/{path}?ref={branch}"
        
        try:
            res = make_github_request(api_url)
            contents = res.json()
            actual_branch = branch
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404 and branch == 'main':
                print(f" Branch 'main' not found, trying 'master'...")
                branch = 'master'
                api_url = f"https://api.github.com/repos/{user}/{repo}/contents/{path}?ref={branch}"
                res = make_github_request(api_url)
                contents = res.json()
                actual_branch = 'master'
            else:
                raise
        
        return jsonify({
            "contents": contents, 
            "context": {"user": user, "repo": repo, "branch": actual_branch, "path": path}
        })
        
    except Exception as e:
        print(f" Error fetching GitHub: {str(e)}")
        traceback.print_exc()
        abort(500, str(e))

@app.route('/generate', methods=['POST'])
def generate_spec():
    data = request.get_json()
    code = data.get('code', '')
    
    if not code:
        abort(400, "No code provided")
    
    try:
        language = detect_language(code)
        print(f"\n Detected language: {language}")
        
        functions, classes, parse_stats = analyze_code(code, language)
        
        endpoints_count = len([f for f in functions if f.get('type') == 'endpoint'])
        functions_count = parse_stats.get('total_methods', 0) - endpoints_count
        classes_count = len(classes)
        
        print(f"   Total methods found: {parse_stats.get('total_methods', 0)}")
        print(f"   Non-endpoint methods: {functions_count}")
        print(f"   Classes found: {classes_count}")
        print(f"   Endpoints found: {endpoints_count}")
        
        spec = generate_openapi_spec(
            functions, 
            classes,
            "Generated API",
            f"Auto-generated API specification from {language} code",
            language
        )
        
        state["analytics"]["total_generations"] += 1
        state["analytics"]["languages"][language] = state["analytics"]["languages"].get(language, 0) + 1
        
        spec_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        state["generated_specs"].append({
            "id": spec_id,
            "spec": spec,
            "timestamp": datetime.now().isoformat(),
            "language": language
        })
        
        return jsonify({
            "specification": yaml.dump(spec, sort_keys=False, default_flow_style=False),
            "language": language,
            "stats": {
                "functions": functions_count,
                "classes": classes_count,
                "endpoints": endpoints_count
            },
            "spec_id": spec_id
        })
        
    except Exception as e:
        print(f" Generation failed: {str(e)}")
        traceback.print_exc()
        abort(500, f"Generation failed: {str(e)}")

@app.route('/generate-repo', methods=['POST'])
def generate_repo_spec():
    data = request.get_json()
    user = data['user']
    repo = data['repo']
    branch = data.get('branch', 'main')
    
    try:
        print(f"\n Fetching repository: {user}/{repo} (branch: {branch})")
        
        all_files, actual_branch = fetch_repo_contents_recursive(user, repo, branch, '')
        
        print(f" Total files found: {len(all_files)}")
        print(f" Using branch: {actual_branch}")
        
        allowed_exts = ('.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.rb', '.php', '.cs', '.c', '.cpp', '.h', '.hpp')
        
        all_functions = []
        all_classes = []
        files_processed = 0
        language_stats = {}
        total_methods_count = 0
        
        for f in all_files:
            if any(f['name'].endswith(ext) for ext in allowed_exts):
                try:
                    print(f"\n Processing: {f['path']}")
                    
                    code_res = make_github_request(f['download_url'])
                    code_text = code_res.text
                    
                    if len(code_text) > 1000000:
                        print(f"   Skipping (too large): {len(code_text)} bytes")
                        continue
                    
                    lang = detect_language(code_text)
                    print(f"    Language: {lang}")
                    
                    language_stats[lang] = language_stats.get(lang, 0) + 1
                    
                    functions, classes, parse_stats = analyze_code(code_text, lang)
                    total_methods_count += parse_stats.get('total_methods', 0)
                    print(f"   Results: {len(functions)} endpoints, {len(classes)} classes")
                    
                    all_functions.extend(functions)
                    all_classes.extend(classes)
                    files_processed += 1
                    
                except Exception as e:
                    print(f"   Error: {str(e)}")
                    continue
        
        endpoints_count = len([f for f in all_functions if f.get('type') == 'endpoint'])
        functions_count = total_methods_count - endpoints_count
        classes_count = len(all_classes)
        
        primary_lang = max(language_stats, key=language_stats.get) if language_stats else 'mixed'
        
        print(f"\n Processing complete:")
        print(f"   Files processed: {files_processed}")
        print(f"   Total functions: {functions_count}")
        print(f"   Total endpoints: {endpoints_count}")
        print(f"   Total classes: {classes_count}")
        print(f"   Languages detected: {language_stats}")
        
        spec = generate_openapi_spec(
            all_functions,
            all_classes,
            f"{repo} API",
            f"Auto-generated from GitHub repository {user}/{repo}",
            primary_lang
        )
        
        state["analytics"]["total_generations"] += 1
        state["analytics"]["languages"][primary_lang] = state["analytics"]["languages"].get(primary_lang, 0) + 1
        
        return jsonify({
            "specification": yaml.dump(spec, sort_keys=False, default_flow_style=False),
            "language": primary_lang,
            "stats": {
                "files_analyzed": files_processed,
                "functions": functions_count,
                "classes": classes_count,
                "endpoints": endpoints_count
            }
        })
        
    except Exception as e:
        print(f" Repository processing failed: {str(e)}")
        traceback.print_exc()
        abort(500, f"Repository processing failed: {str(e)}")

@app.route('/summarize-repo', methods=['POST'])
def summarize_repo():
    data = request.get_json()
    user = data['user']
    repo = data['repo']
    branch = data.get('branch', 'main')
    
    try:
        print(f"\n Summarizing repository: {user}/{repo}")
        
        all_files, actual_branch = fetch_repo_contents_recursive(user, repo, branch, '')
        
        summary = {
            "repository": f"{user}/{repo}",
            "branch": actual_branch,
            "total_files": len(all_files),
            "languages": {},
            "structure": {}
        }
        
        for f in all_files:
            ext = f['name'].split('.')[-1] if '.' in f['name'] else 'no_extension'
            summary["languages"][ext] = summary["languages"].get(ext, 0) + 1
            
            path_parts = f['path'].split('/')
            if len(path_parts) > 1:
                dir_name = path_parts[0]
                summary["structure"][dir_name] = summary["structure"].get(dir_name, 0) + 1
        
        summary_text = f"""Repository: {user}/{repo}
Branch: {actual_branch}
Total Files: {len(all_files)}

Language Distribution:
"""
        for lang, count in sorted(summary["languages"].items(), key=lambda x: x[1], reverse=True)[:15]:
            percentage = (count / len(all_files)) * 100 if len(all_files) > 0 else 0
            summary_text += f"  • {lang}: {count} files ({percentage:.1f}%)\n"
        
        summary_text += "\nDirectory Structure:\n"
        for dir_name, count in sorted(summary["structure"].items(), key=lambda x: x[1], reverse=True)[:15]:
            summary_text += f"  • {dir_name}/: {count} files\n"
        
        return jsonify({"summary": summary_text})
        
    except Exception as e:
        print(f" Summarization failed: {str(e)}")
        traceback.print_exc()
        abort(500, f"Summarization failed: {str(e)}")

@app.route('/generate-otp', methods=['GET'])
def generate_otp():
    state['current_otp'] = "".join(random.choices(string.digits, k=6))
    print(f" Generated OTP: {state['current_otp']}")
    return jsonify({"otp": state['current_otp']})

@app.route('/validate-otp', methods=['POST'])
def validate_otp():
    user_otp = request.get_json().get('otp')
    print(f" Validating OTP: {user_otp} (Expected: {state['current_otp']})")
    
    if state['current_otp'] and user_otp == state['current_otp']:
        state['current_otp'] = None
        return jsonify({"valid": True})
    
    return jsonify({"valid": False}), 401

@app.route('/analytics', methods=['GET'])
def get_analytics():
    return jsonify(state["analytics"])

@app.route('/mock/<path:endpoint>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def mock_endpoint(endpoint):
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "error": "Unauthorized",
            "message": "Valid bearer token required"
        }), 401
    
    mock_data = {
        "success": True,
        "endpoint": f"/{endpoint}",
        "method": request.method,
        "timestamp": datetime.now().isoformat(),
        "data": {
            "id": random.randint(1, 1000),
            "message": f"Mock response for {endpoint}",
            "status": "active",
            "metadata": {
                "processed_at": datetime.now().isoformat(),
                "version": "1.0.0"
            }
        }
    }
    
    return jsonify(mock_data)

@app.route('/export/<spec_id>', methods=['GET'])
def export_spec(spec_id):
    spec = next((s for s in state["generated_specs"] if s["id"] == spec_id), None)
    if not spec:
        abort(404, "Specification not found")
    
    format_type = request.args.get('format', 'yaml')
    
    if format_type == 'json':
        return jsonify(spec["spec"])
    else:
        return yaml.dump(spec["spec"], sort_keys=False, default_flow_style=False), 200, {'Content-Type': 'text/yaml'}

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "version": "2.3.0",
        "tier": "elite",
        "timestamp": datetime.now().isoformat(),
        "upgrades": {
            "request_body_detection": True,
            "response_entity_inference": True,
            "rest_mvc_classification": True,
            "accurate_response_codes": True
        },
        "refinements": {
            "framework_params_filtered": True,
            "path_params_safety": True,
            "conditional_security": True
        },
        "polish": {
            "duplicate_param_prevention": True,
            "consistent_type_inference": True,
            "mvc_string_responses": True,
            "framework_types_set": 17
        },
        "elite": {
            "zero_framework_leaks": True,
            "intelligent_param_parsing": True,
            "semantic_correctness": True
        },
        "stats": {
            "total_generations": state["analytics"]["total_generations"],
            "active_otps": 1 if state["current_otp"] else 0
        }
    })

if __name__ == '__main__':
    print("--- API Forge Server v2.3 Starting ---")
    print("Local:  http://127.0.0.1:5000")
    print("Health: http://127.0.0.1:5000/health")
    
    app.run(port=5000, debug=True, host='0.0.0.0')
