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
        self.timeout = int(api_config.get('timeout', 300))
        self.verify_ssl = api_config.get('verify_ssl', 'false').lower() == 'true'
        
        # Minimum commands required before AI can conclude
        self.min_commands_required = int(api_config.get('min_commands_required', 10))
        
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
        self.audit.log('INFO', f'Infrastructure loaded: {len(self.infrastructure)} hosts')

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
                        "content": f"❌ REJECTED: You must execute at least {self.min_commands_required} diagnostic commands before concluding.\n\n" +
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
                "content": f"❌ REJECTED: That command is too similar to already executed commands.\n\n" +
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

ABSOLUTE RULES:
1. You MUST execute at least {self.min_commands_required} diagnostic commands before you can conclude
2. NEVER repeat a command that has already been executed
3. NEVER suggest minor variations (like changing head -20 to head -10)
4. Suggest COMPLETELY DIFFERENT approaches
5. All commands must be READ-ONLY (no rm, delete, truncate, write operations)
6. Permission errors on 'lost+found' are NORMAL - ignore them
7. You can run commands on ANY host in the infrastructure - specify TARGET_HOST
8. For containers/VMs with issues, you may also check the hypervisor (hbpm01)
9. For network equipment, NAS, or appliances, use the jumpserver (hbcsrv14)
10. Consider checking related services (e.g., if MySQL disk is full, check the app servers using it)

AVAILABLE DIAGNOSTIC APPROACHES:
- Disk usage: du, find, ncdu, ls, df, lsof
- Process analysis: ps, top, lsof, /proc
- Log analysis: journalctl, /var/log/*, dmesg
- Docker: docker ps, docker stats, docker system df
- Proxmox (on hbpm01): pct exec, pvesm, zfs list, lvs
- Service status: systemctl, service
- Network: ss, netstat, ip
- Filesystem: mount, findmnt, tune2fs, xfs_info"""

        messages.append({
            "role": "system",
            "content": system_content
        })

        # Track executed commands with their targets
        executed_cmds = []

        # Add conversation history as proper message pairs
        for item in history:
            if item.get('executed'):
                target = item.get('target_host', context['hostname'])
                executed_cmds.append(f"{target}: {item['command']}")

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
⚠️  COMMANDS ALREADY EXECUTED - DO NOT REPEAT OR VARY THESE:
{'='*80}
"""

        if executed_cmds:
            for i, cmd in enumerate(executed_cmds, 1):
                current_prompt += f"❌ {i}. {cmd}\n"
        else:
            current_prompt += "✓ No commands executed yet\n"

        current_prompt += f"""
{'='*80}

PROGRESS: {num_executed}/{self.min_commands_required} commands executed (minimum required: {self.min_commands_required})

CURRENT PROBLEM:
- Alerting Host: {context['hostname']}
- Mount Point: {context['mount_point']}
- Usage: {context['usage_percent']}% ({context['used_gb']}GB used / {context['total_gb']}GB total)
- Free Space: {context['free_gb']}GB

YOUR TASK:
Analyze the problem and suggest the next diagnostic command. You may:
1. Run a command on the alerting host ({context['hostname']})
2. Run a command on the hypervisor (hbpm01) to check container/VM level
3. Run a command on a related host (e.g., check what's writing to this server)

Use a COMPLETELY DIFFERENT APPROACH than the commands already executed.

RESPONSE FORMAT (exactly as shown):
TARGET_HOST: [hostname - must be from infrastructure list]
NEXT_COMMAND: [single command, read-only only]
EXPLANATION: [why this helps diagnose the issue]

{'DO NOT use DIAGNOSIS_COMPLETE until you have executed at least ' + str(self.min_commands_required) + ' commands!' if num_executed < self.min_commands_required else 'You may now use DIAGNOSIS_COMPLETE if you have enough information:'}
"""

        if num_executed >= self.min_commands_required:
            current_prompt += """
OR if you have enough information to conclude:
DIAGNOSIS_COMPLETE: true
FINAL_ANALYSIS: [your analysis of what's consuming space and why]
RECOMMENDED_ACTIONS:
1. [specific action with command if applicable]
2. [another action]
"""

        messages.append({
            "role": "user",
            "content": current_prompt
        })

        return messages

    def _send_to_ollama(self, messages: List[Dict]) -> Optional[str]:
        """Send to Ollama's native chat API"""

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "num_ctx": 16384,
                "num_predict": 1024,
                "top_p": 0.9,
                "repeat_penalty": 1.3
            }
        }

        headers = {
            "Content-Type": "application/json"
        }

        # Add Authorization header only if API key is present
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            self.audit.log('DEBUG', 'Using API key for authentication')
        else:
            self.audit.log('WARNING', 'No API key configured - request may fail')

        try:
            self.audit.log('INFO', f'Sending request to Ollama ({len(messages)} messages)')
            self.audit.log('DEBUG', f'Request URL: {self.chat_endpoint}')

            response = requests.post(
                self.chat_endpoint,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if response.status_code != 200:
                self.audit.log('ERROR', f'Ollama returned status {response.status_code}',
                             {'response': response.text[:500]})
                return None

            data = response.json()
            content = data.get('message', {}).get('content', '')

            self.audit.log('INFO', f'Received response ({len(content)} chars)')
            return content

        except requests.exceptions.Timeout:
            self.audit.log('ERROR', f'Ollama API timeout after {self.timeout}s')
            return None
        except Exception as e:
            self.audit.log('ERROR', f'Ollama API error: {str(e)}')
            return None

    def _parse_interactive_response(self, response: str) -> Dict:
        """Parse Ollama response with target host support"""

        # Check if diagnosis is complete
        if re.search(r'DIAGNOSIS_COMPLETE:\s*true', response, re.IGNORECASE):

            analysis_match = re.search(
                r'FINAL_ANALYSIS:\s*(.+?)(?=RECOMMENDED_ACTIONS:|$)',
                response,
                re.DOTALL | re.IGNORECASE
            )
            final_analysis = analysis_match.group(1).strip() if analysis_match else ''

            actions = []
            actions_section = re.search(
                r'RECOMMENDED_ACTIONS:(.*?)$',
                response,
                re.DOTALL | re.IGNORECASE
            )
            if actions_section:
                actions_text = actions_section.group(1)
                action_lines = re.findall(r'^\d+\.\s*(.+?)$', actions_text, re.MULTILINE)
                actions = [line.strip() for line in action_lines if line.strip()]

            return {
                'success': True,
                'done': True,
                'final_analysis': final_analysis,
                'recommended_actions': actions,
                'raw_response': response  # Keep raw response for rejection handling
            }

        # Extract target host (new field)
        target_match = re.search(r'TARGET_HOST:\s*(\S+)', response, re.IGNORECASE)
        target_host = target_match.group(1).strip() if target_match else None

        # Extract next command
        command_match = re.search(r'NEXT_COMMAND:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
        explanation_match = re.search(r'EXPLANATION:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)

        if command_match:
            return {
                'success': True,
                'done': False,
                'target_host': target_host,
                'command': command_match.group(1).strip(),
                'explanation': explanation_match.group(1).strip() if explanation_match else ''
            }

        # Try to extract command even without proper format (fallback)
        self.audit.log('WARNING', 'Response not in expected format, attempting fallback parse',
                      {'response_preview': response[:200]})

        return {
            'success': False,
            'error': 'Could not parse Ollama response',
            'raw_response': response[:500]
        }
