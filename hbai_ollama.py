#!/usr/bin/env python3
"""
Interactive AI Analyzer Module for HBAI-MON v3.1
Uses direct Ollama API with command deduplication and infrastructure awareness
"""

import requests
import json
import time
import re
import difflib
import os
from typing import Dict, List, Optional
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
CONFIG_DIR = "/etc/hbai-mon"
INFRASTRUCTURE_FILE = f"{CONFIG_DIR}/infrastructure.txt"


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class InteractiveAIAnalyzer:
    """Interactive AI analyzer using Ollama's native chat API"""

    def __init__(self, api_config: dict, audit_logger):
        # Debug: Log what we received
        audit_logger.log('INFO', 'Received api_config', {'keys': list(api_config.keys())})

        # Ollama is at /ollama path on the Open-WebUI server
        base_url = api_config.get('url', 'https://ai.internal.boehmecke.org')
        self.api_url = f"{base_url}/ollama"
        self.model = api_config.get('model', 'qwen2.5-coder:3b')
        # Try multiple possible key names
        self.api_key = api_config.get('key') or api_config.get('api_key', '')
        self.timeout = int(api_config.get('timeout', 600))
        self.verify_ssl = api_config.get('verify_ssl', 'false').lower() == 'true'
        
        # Minimum commands required before AI can conclude
        self.min_commands_required = int(api_config.get('min_commands_required', 10))
        
        # Model parameters from config
        self.temperature = float(api_config.get('temperature', 0.7))
        self.num_ctx = int(api_config.get('num_ctx', 16384))
        self.num_predict = int(api_config.get('num_predict', 4096))
        self.top_p = float(api_config.get('top_p', 0.9))
        self.top_k = int(api_config.get('top_k', 40))
        self.repeat_penalty = float(api_config.get('repeat_penalty', 1.3))
        
        self.audit = audit_logger

        # Ollama native chat endpoint
        self.chat_endpoint = f"{self.api_url}/api/chat"

        # Load infrastructure info
        self.infrastructure = self._load_infrastructure()

        self.audit.log('INFO', f'Initialized Ollama API: {self.chat_endpoint}')
        self.audit.log('INFO', f'Model: {self.model}')
        self.audit.log('INFO', f'Minimum commands required: {self.min_commands_required}')
        self.audit.log('INFO', f'API key present: {bool(self.api_key)}')
        self.audit.log('INFO', f'API key length: {len(self.api_key) if self.api_key else 0}')
        if self.api_key:
            self.audit.log('INFO', f'API key prefix: {self.api_key[:10]}...')
        self.audit.log('INFO', f'Infrastructure loaded: {len(self.infrastructure)} chars')

    def _load_infrastructure(self) -> str:
        """Load infrastructure description from file"""
        if os.path.exists(INFRASTRUCTURE_FILE):
            try:
                with open(INFRASTRUCTURE_FILE, 'r') as f:
                    return f.read()
            except Exception as e:
                self.audit.log('WARNING', f'Failed to load infrastructure file: {e}')
        return "Infrastructure file not available."

    def _is_command_similar(self, new_command: str, existing_commands: List[str], threshold: float = 0.7) -> bool:
        """Check if new command is too similar to any existing command"""

        # Normalize commands (remove extra spaces, lowercase)
        new_cmd_normalized = ' '.join(new_command.lower().split())

        for existing in existing_commands:
            existing_normalized = ' '.join(existing.lower().split())

            # Calculate similarity ratio
            similarity = difflib.SequenceMatcher(None, new_cmd_normalized, existing_normalized).ratio()

            if similarity > threshold:
                self.audit.log('WARNING', f'Command too similar',
                             {'new': new_command, 'existing': existing, 'similarity': f'{similarity:.2f}'})
                return True

        return False

    def get_next_diagnostic_command(self, problem_context: Dict,
                                   conversation_history: List[Dict]) -> Dict:
        """Get next command with similarity checking"""

        # Track already executed commands
        executed_commands = [item['command'] for item in conversation_history if item.get('executed')]
        num_executed = len(executed_commands)

        # Try up to 3 times to get a unique command
        max_attempts = 3
        messages = self._build_conversation_messages(problem_context, conversation_history)

        for attempt in range(max_attempts):

            # Get AI response
            response = self._send_to_ollama(messages)

            if not response:
                return {'success': False, 'error': 'No response from Ollama'}

            # Parse response
            result = self._parse_interactive_response(response)

            if not result['success']:
                return result

            # CHECK: AI wants to finish, but have we executed enough commands?
            if result.get('done', False):
                if num_executed >= self.min_commands_required:
                    # OK to finish
                    self.audit.log('INFO', f'AI completed diagnosis after {num_executed} commands (minimum: {self.min_commands_required})')
                    return result
                else:
                    # REJECT - not enough commands yet
                    self.audit.log('WARNING', f'AI tried to finish early after only {num_executed} commands (minimum: {self.min_commands_required})')
                    
                    # Tell AI to continue
                    messages.append({
                        "role": "assistant",
                        "content": result.get('raw_response', 'DIAGNOSIS_COMPLETE: true')
                    })
                    messages.append({
                        "role": "user",
                        "content": f"REJECTED: You must execute at least {self.min_commands_required} diagnostic commands before concluding.\n\n" +
                                  f"So far you have only executed {num_executed} commands.\n\n" +
                                  f"You need to run {self.min_commands_required - num_executed} more commands.\n\n" +
                                  f"Continue with the next diagnostic command using a different approach."
                    })
                    continue  # Try again

            # Check if command is too similar to existing ones
            new_command = result.get('command', '')

            if not self._is_command_similar(new_command, executed_commands, threshold=0.7):
                # Command is sufficiently different
                self.audit.log('INFO', f'AI suggested unique command: {new_command[:50]}...')
                return result

            # Command is too similar - tell AI and retry
            self.audit.log('INFO', f'AI suggested similar command (attempt {attempt+1}/{max_attempts})',
                         {'suggested': new_command})

            # Add rejection to conversation
            messages.append({
                "role": "assistant",
                "content": f"TARGET_HOST: {result.get('target_host', problem_context['hostname'])}\nNEXT_COMMAND: {new_command}\nEXPLANATION: {result.get('explanation', '')}"
            })
            messages.append({
                "role": "user",
                "content": f"REJECTED: That command is too similar to already executed commands.\n\n" +
                          f"Already executed:\n" +
                          '\n'.join(f"- {cmd}" for cmd in executed_commands) +
                          f"\n\nYour suggestion '{new_command}' is basically the same.\n\n" +
                          f"Suggest something COMPLETELY DIFFERENT - a different approach entirely."
            })

        # Failed to get unique command after max attempts
        return {
            'success': False,
            'error': f'AI could not suggest a unique command after {max_attempts} attempts. Try larger model or manual intervention.'
        }

    def _build_conversation_messages(self, context: Dict, history: List[Dict]) -> List[Dict]:
        """Build proper conversation messages for Ollama chat API"""

        messages = []
        
        # Count executed commands
        num_executed = len([h for h in history if h.get('executed')])

        # System message with infrastructure context and strict rules
        system_content = f"""You are an expert Linux systems administrator conducting interactive diagnosis on a home infrastructure.

INFRASTRUCTURE OVERVIEW:
{self.infrastructure}

RESPONSE RULES:
1. Suggest exactly ONE command per response - no more, no less
2. Wait for the command output before suggesting the next command
3. You will receive the history of all previously executed commands and their outputs
4. You MUST execute at least {self.min_commands_required} diagnostic commands before concluding
5. If more commands are needed after {self.min_commands_required}, continue until you have enough information
6. NEVER repeat a command that has already been executed
7. NEVER suggest minor variations of previous commands (e.g., changing head -20 to head -10)
8. Each command should explore a DIFFERENT diagnostic angle

COMMAND REQUIREMENTS:
1. All commands must be READ-ONLY (no rm, delete, truncate, write operations)
2. Commands must be COMPLETE and EXECUTABLE - no placeholders like <container_id> or <path>
3. If you need specific IDs or paths, first suggest a command to discover them
4. Permission errors on 'lost+found' directories are NORMAL - ignore them
5. You may use backticks (`) in MySQL queries for column/table identifiers - they will be escaped automatically

MULTI-HOST DIAGNOSIS:
1. You can run commands on ANY host in the infrastructure - specify TARGET_HOST
2. For containers/VMs with issues, also consider checking the hypervisor (hbpm01)
3. For network equipment, NAS, or appliances, access via jumpserver (hbcsrv14)
4. Consider checking related services (e.g., if MySQL disk is full, check which apps use that database)

MYSQL COMMANDS:
- Use -p WITHOUT a password value - credentials are auto-injected
- Correct: mysql -u root -p -e "SELECT ..."
- Correct: mysqladmin -u root -p status
- WRONG: mysql -u root -p'password' -e "..."
- You CAN use backticks for MySQL identifiers (they are escaped automatically)
- Example: SELECT table_schema AS `Database`, SUM(data_length) AS `Size` FROM information_schema.tables

DIAGNOSTIC GOAL:
Your goal is to find ROOT CAUSES and propose LONG-TERM SOLUTIONS, not quick patches.

For example, if a MySQL partition is full:
- Identify WHICH database is consuming the most space
- Determine WHY it is growing (logs, old data, lack of retention policy)
- Propose HOUSEKEEPING solutions (log rotation, data archival, retention policies, scheduled cleanup jobs)
- Do NOT just suggest deleting files as a one-time fix

AVAILABLE DIAGNOSTIC TOOLS:
- Disk: du, find, ncdu, ls, df, lsof
- Processes: ps, top, lsof, /proc
- Logs: journalctl, /var/log/*, dmesg
- Docker: docker ps, docker stats, docker system df
- Proxmox (on hbpm01): pct exec, pvesm, zfs list, lvs
- Services: systemctl, service
- Network: ss, netstat, ip
- Filesystem: mount, findmnt, tune2fs, xfs_info
- MySQL: SHOW BINARY LOGS, SHOW VARIABLES, information_schema queries

OUTPUT FORMAT:
Use PLAIN TEXT only - no Markdown (no **, no ```, no ###, no bullet points)

For each diagnostic step, respond with exactly:
TARGET_HOST: hostname.internal.boehmecke.org
NEXT_COMMAND: complete executable command
EXPLANATION: brief reason why this helps

When you have gathered enough information (minimum {self.min_commands_required} commands), respond with:
DIAGNOSIS_COMPLETE: true
ROOT_CAUSE: what is causing the problem and why
LONG_TERM_SOLUTION: permanent fix with implementation steps
IMMEDIATE_ACTIONS: if urgent, what to do right now
PREVENTIVE_MEASURES: how to prevent this in the future
COMMANDS_TO_IMPLEMENT: specific commands to implement the solution (numbered list)"""

        messages.append({
            "role": "system",
            "content": system_content
        })

        # Track executed commands with their targets and outputs
        executed_cmds = []

        # Add conversation history as proper message pairs
        for item in history:
            if item.get('executed'):
                target = item.get('target_host', context['hostname'])
                cmd_summary = f"{target}: {item['command']}"
                
                # Include truncated output in the summary
                output = item.get('stdout', '')
                if len(output) > 1000:
                    output = output[:1000] + "\n... (truncated)"
                
                executed_cmds.append({
                    'summary': cmd_summary,
                    'output': output,
                    'success': item.get('success', False)
                })

                # User executed command
                messages.append({
                    "role": "user",
                    "content": f"I executed on {target}: {item['command']}"
                })

                # Assistant sees the result
                if item.get('success'):
                    result = f"Output:\n{item['stdout'][:3000]}"
                    if len(item.get('stdout', '')) > 3000:
                        result += "\n... (truncated)"
                else:
                    result = f"Error: {item.get('stderr', 'Unknown error')}"

                messages.append({
                    "role": "assistant",
                    "content": result
                })

        # Build current prompt
        current_prompt = f"""
{'='*80}
PREVIOUSLY EXECUTED COMMANDS AND RESULTS:
{'='*80}
"""

        if executed_cmds:
            for i, cmd_info in enumerate(executed_cmds, 1):
                status = "OK" if cmd_info['success'] else "FAILED"
                current_prompt += f"\n{i}. [{status}] {cmd_info['summary']}\n"
                if cmd_info['output']:
                    # Indent output for readability
                    indented_output = '\n'.join(f"   {line}" for line in cmd_info['output'].split('\n')[:20])
                    current_prompt += f"{indented_output}\n"
                    if len(cmd_info['output'].split('\n')) > 20:
                        current_prompt += "   ... (output truncated)\n"
        else:
            current_prompt += "No commands executed yet.\n"

        current_prompt += f"""
{'='*80}

PROGRESS: {num_executed}/{self.min_commands_required} commands executed (minimum required: {self.min_commands_required})

CURRENT PROBLEM:
- Alerting Host: {context['hostname']}
- Mount Point: {context['mount_point']}
- Usage: {context['usage_percent']}% ({context['used_gb']}GB used / {context['total_gb']}GB total)
- Free Space: {context['free_gb']}GB

YOUR TASK:
Analyze the information gathered so far and suggest the NEXT SINGLE diagnostic command.
Focus on finding the ROOT CAUSE, not just symptoms.
Think about what LONG-TERM SOLUTION would prevent this problem from recurring.

Remember:
- Suggest exactly ONE command
- Use a DIFFERENT approach than previous commands
- {"You need " + str(self.min_commands_required - num_executed) + " more commands before you can conclude" if num_executed < self.min_commands_required else "You may conclude if you have enough information, or continue investigating"}

RESPOND WITH:
TARGET_HOST: hostname.internal.boehmecke.org
NEXT_COMMAND: single complete executable command
EXPLANATION: why this command helps find the root cause
"""

        if num_executed >= self.min_commands_required:
            current_prompt += """
OR if you have identified the root cause:
DIAGNOSIS_COMPLETE: true
ROOT_CAUSE: what is causing the problem and why it happened
LONG_TERM_SOLUTION: permanent fix with specific implementation steps
IMMEDIATE_ACTIONS: urgent steps if disk is critically full (optional)
PREVENTIVE_MEASURES: how to prevent recurrence (monitoring, alerts, automation)
COMMANDS_TO_IMPLEMENT: numbered list of commands to implement the solution
"""

        messages.append({
            "role": "user",
            "content": current_prompt
        })

        return messages

    def _send_to_ollama(self, messages: List[Dict]) -> Optional[str]:
        """Send to Ollama's native chat API with streaming for real-time feedback"""

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,  # Enable streaming
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
                "top_p": self.top_p,
                "top_k": self.top_k,
                "repeat_penalty": self.repeat_penalty
            }
        }

        headers = {
            "Content-Type": "application/json"
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            self.audit.log('INFO', f'Sending request to Ollama ({len(messages)} messages)')
            self.audit.log('DEBUG', f'Request URL: {self.chat_endpoint}')
            self.audit.log('DEBUG', f'Model: {self.model}, timeout: {self.timeout}s')

            start_time = time.time()
            
            # Status tracking
            in_think_block = False
            think_started = False
            answer_started = False
            token_count = 0
            last_status_update = start_time
            status_update_interval = 5  # Update elapsed time every 5 seconds
            
            full_response = ""
            
            # Print initial status
            print(f"\n{Colors.OKCYAN}[...] Waiting for AI response...{Colors.ENDC}", end='', flush=True)

            with requests.post(
                self.chat_endpoint,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                stream=True
            ) as response:
                
                if response.status_code != 200:
                    self.audit.log('ERROR', f'Ollama returned status {response.status_code}',
                                 {'response': response.text[:500]})
                    print(f"\n{Colors.FAIL}[X] API error: {response.status_code}{Colors.ENDC}")
                    return None

                for line in response.iter_lines():
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    
                    # Extract token content
                    content = data.get('message', {}).get('content', '')
                    if content:
                        full_response += content
                        token_count += 1  # Approximate: 1 chunk = 1 token
                        
                        # Check for <think> tag start
                        if '<think>' in content.lower() and not think_started:
                            think_started = True
                            in_think_block = True
                            elapsed = time.time() - start_time
                            print(f"\r{Colors.WARNING}[THINK] AI is reasoning... [{elapsed:.0f}s, ~{token_count} tokens]{Colors.ENDC}      ", end='', flush=True)
                            self.audit.log('DEBUG', f'AI started thinking at {elapsed:.1f}s')
                        
                        # Check for </think> tag end
                        elif '</think>' in content.lower() and in_think_block:
                            in_think_block = False
                            answer_started = True
                            elapsed = time.time() - start_time
                            print(f"\r{Colors.OKGREEN}[DONE] Thinking complete, generating answer... [{elapsed:.0f}s, ~{token_count} tokens]{Colors.ENDC}      ", end='', flush=True)
                            self.audit.log('DEBUG', f'AI finished thinking at {elapsed:.1f}s, ~{token_count} tokens used for thinking')
                        
                        # Periodic status update while thinking
                        elif in_think_block:
                            current_time = time.time()
                            if current_time - last_status_update >= status_update_interval:
                                elapsed = current_time - start_time
                                print(f"\r{Colors.WARNING}[THINK] AI is reasoning... [{elapsed:.0f}s, ~{token_count} tokens]{Colors.ENDC}      ", end='', flush=True)
                                last_status_update = current_time
                        
                        # Status update while answering
                        elif answer_started or not think_started:
                            current_time = time.time()
                            if current_time - last_status_update >= status_update_interval:
                                elapsed = current_time - start_time
                                status_msg = "generating answer" if answer_started else "processing"
                                print(f"\r{Colors.OKCYAN}[GEN] AI is {status_msg}... [{elapsed:.0f}s, ~{token_count} tokens]{Colors.ENDC}      ", end='', flush=True)
                                last_status_update = current_time
                    
                    # Check if done
                    if data.get('done', False):
                        elapsed = time.time() - start_time
                        done_reason = data.get('done_reason', 'complete')
                        
                        # Get actual token counts from final response
                        eval_count = data.get('eval_count', token_count)
                        prompt_eval_count = data.get('prompt_eval_count', 0)
                        
                        print(f"\r{Colors.OKGREEN}[OK] Response complete [{elapsed:.1f}s, {eval_count} out / {prompt_eval_count} prompt tokens]{Colors.ENDC}      ")
                        
                        self.audit.log('INFO', f'Response complete in {elapsed:.1f}s', {
                            'done_reason': done_reason,
                            'output_tokens': eval_count,
                            'prompt_tokens': prompt_eval_count,
                            'total_chars': len(full_response)
                        })
                        
                        if done_reason == 'length':
                            print(f"{Colors.WARNING}[!] Response may be truncated (hit token limit){Colors.ENDC}")
                            self.audit.log('WARNING', 'Response truncated due to token limit')
                        
                        break

            # Final logging
            self.audit.log('DEBUG', f'Response START: {full_response[:500]}')
            if len(full_response) > 500:
                self.audit.log('DEBUG', f'Response END: {full_response[-500:]}')

            return full_response

        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            print(f"\r{Colors.FAIL}[X] Request timed out after {elapsed:.0f}s{Colors.ENDC}      ")
            self.audit.log('ERROR', f'Ollama API timeout after {self.timeout}s')
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"\r{Colors.FAIL}[X] Connection error: {str(e)[:50]}{Colors.ENDC}      ")
            self.audit.log('ERROR', f'Ollama connection error: {str(e)}')
            return None
        except Exception as e:
            print(f"\r{Colors.FAIL}[X] Error: {str(e)[:50]}{Colors.ENDC}      ")
            self.audit.log('ERROR', f'Ollama API error: {str(e)}')
            return None

    def _parse_interactive_response(self, response: str) -> Dict:
        """Parse Ollama response with target host support - handles Markdown formatting and thinking tags"""

        # Log raw response for debugging
        self.audit.log('DEBUG', f'Raw response length: {len(response)}')
        self.audit.log('DEBUG', f'Raw response first 300 chars: {response[:300]}')
        
        # Check for <think> tags before stripping
        think_matches = list(re.finditer(r'<think>', response, re.IGNORECASE))
        think_end_matches = list(re.finditer(r'</think>', response, re.IGNORECASE))
        self.audit.log('DEBUG', f'Found {len(think_matches)} <think> tags, {len(think_end_matches)} </think> tags')
        
        if think_matches:
            for i, match in enumerate(think_matches):
                self.audit.log('DEBUG', f'<think> tag {i+1} at position {match.start()}')
        if think_end_matches:
            for i, match in enumerate(think_end_matches):
                self.audit.log('DEBUG', f'</think> tag {i+1} at position {match.start()}')

        # Strip <think> blocks (some models output reasoning) - handle multiple and mid-line occurrences
        original_len = len(response)
        
        # First, remove complete <think>...</think> blocks
        response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL | re.IGNORECASE)
        
        # Also handle unclosed <think> tags (thinking that continues to end of response)
        response = re.sub(r'<think>.*$', '', response, flags=re.DOTALL | re.IGNORECASE)
        
        # Clean up any leftover artifacts from mid-line think tags
        response = re.sub(r'</?think[^>]*>', '', response, flags=re.IGNORECASE)
        
        # Clean up extra whitespace and blank lines
        response = re.sub(r'\n\s*\n', '\n', response)
        response = response.strip()
        
        self.audit.log('DEBUG', f'After think-stripping: {original_len} -> {len(response)} chars')
        self.audit.log('DEBUG', f'Stripped response: {response[:300] if response else "(empty)"}')

        # If response is empty after stripping, it was all thinking
        if not response:
            self.audit.log('WARNING', 'Response contained only <think> block, no actual answer')
            return {
                'success': False,
                'error': 'AI only provided reasoning without answer',
                'raw_response': response[:500]
            }

        # Check if diagnosis is complete
        if re.search(r'DIAGNOSIS_COMPLETE:\s*true', response, re.IGNORECASE):

            root_cause_match = re.search(
                r'ROOT_CAUSE:\s*(.+?)(?=LONG_TERM_SOLUTION:|$)',
                response,
                re.DOTALL | re.IGNORECASE
            )
            root_cause = root_cause_match.group(1).strip() if root_cause_match else ''

            solution_match = re.search(
                r'LONG_TERM_SOLUTION:\s*(.+?)(?=IMMEDIATE_ACTIONS:|PREVENTIVE_MEASURES:|COMMANDS_TO_IMPLEMENT:|$)',
                response,
                re.DOTALL | re.IGNORECASE
            )
            long_term_solution = solution_match.group(1).strip() if solution_match else ''

            immediate_match = re.search(
                r'IMMEDIATE_ACTIONS:\s*(.+?)(?=PREVENTIVE_MEASURES:|COMMANDS_TO_IMPLEMENT:|$)',
                response,
                re.DOTALL | re.IGNORECASE
            )
            immediate_actions = immediate_match.group(1).strip() if immediate_match else ''

            preventive_match = re.search(
                r'PREVENTIVE_MEASURES:\s*(.+?)(?=COMMANDS_TO_IMPLEMENT:|$)',
                response,
                re.DOTALL | re.IGNORECASE
            )
            preventive_measures = preventive_match.group(1).strip() if preventive_match else ''

            commands_match = re.search(
                r'COMMANDS_TO_IMPLEMENT:(.*?)$',
                response,
                re.DOTALL | re.IGNORECASE
            )
            implementation_commands = []
            if commands_match:
                commands_text = commands_match.group(1)
                cmd_lines = re.findall(r'^\d+\.\s*(.+?)$', commands_text, re.MULTILINE)
                implementation_commands = [line.strip() for line in cmd_lines if line.strip()]

            return {
                'success': True,
                'done': True,
                'root_cause': root_cause,
                'long_term_solution': long_term_solution,
                'immediate_actions': immediate_actions,
                'preventive_measures': preventive_measures,
                'implementation_commands': implementation_commands,
                'final_analysis': root_cause,  # Backward compatibility
                'recommended_actions': implementation_commands,  # Backward compatibility
                'raw_response': response
            }

        # Extract target host - handle Markdown formatting (###, **, etc.)
        target_match = re.search(
            r'TARGET[_\s]*HOST:\s*[*`#]*\s*(\S+)',
            response,
            re.IGNORECASE
        )
        target_host = target_match.group(1).strip() if target_match else None

        # Remove any trailing Markdown characters from hostname
        if target_host:
            target_host = target_host.rstrip('*`#_')

        # Extract next command - more flexible pattern to handle various formats
        command_match = re.search(
            r'NEXT[_\s]*COMMAND:\s*[*`]*\s*(.+?)(?:[*`]*\s*(?:\n|$))',
            response,
            re.IGNORECASE | re.DOTALL
        )
        
        # If that didn't work, try multiline: NEXT_COMMAND:\n<command>
        if not command_match or not command_match.group(1).strip():
            command_match = re.search(
                r'NEXT[_\s]*COMMAND:\s*\n\s*(.+?)(?:\n|$)',
                response,
                re.IGNORECASE
            )

        # Extract explanation - handle bold markers
        explanation_match = re.search(
            r'EXPLANATION:\s*[*-]*\s*(.+?)(?:\n\n|\n-|\n\*|TARGET_HOST:|NEXT_COMMAND:|$)',
            response,
            re.DOTALL | re.IGNORECASE
        )

        if command_match:
            command = command_match.group(1).strip()
            # Clean up Markdown formatting from command
            command = command.strip('`*_#')
            # Remove any newlines within the command
            command = command.split('\n')[0].strip()

            if command:
                explanation = ''
                if explanation_match:
                    explanation = explanation_match.group(1).strip()
                    explanation = re.sub(r'^[*-]\s+', '', explanation)
                    explanation = re.sub(r'\*\*(.+?)\*\*', r'\1', explanation)

                self.audit.log('DEBUG', f'Parsed successfully: target={target_host}, command={command[:50]}')
                return {
                    'success': True,
                    'done': False,
                    'target_host': target_host,
                    'command': command,
                    'explanation': explanation
                }

        # Fallback parse failed
        self.audit.log('WARNING', 'Response not in expected format, attempting fallback parse',
                      {'response_preview': response[:200]})

        return {
            'success': False,
            'error': 'Could not parse Ollama response',
            'raw_response': response[:500]
        }
