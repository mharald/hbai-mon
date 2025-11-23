#!/usr/bin/env python3
"""
Interactive AI Analyzer Module for HBAI-MON v3
Provides conversational AI diagnosis using Ollama with conversation history
"""

import requests
import json
import time
import re
from typing import Dict, List, Optional
import urllib3
from datetime import datetime
import uuid

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class InteractiveAIAnalyzer:
    """Interactive AI analyzer that conducts conversational diagnosis"""
    
    def __init__(self, api_config: dict, audit_logger):
        self.api_url = api_config.get('url', 'https://ai.internal.boehmecke.org')
        self.model = api_config.get('model', 'qwen3:4b')
        self.api_key = api_config.get('key', '')
        self.timeout = int(api_config.get('timeout', 300))
        self.verify_ssl = api_config.get('verify_ssl', 'false').lower() == 'true'
        self.audit = audit_logger
        
        self.chat_endpoint = f"{self.api_url}/api/chat/completions"
        self.chat_new_endpoint = f"{self.api_url}/api/v1/chats/new"
        
        self.messages = []
        self.session_title = None
        self.chat_id = None
        self.chat_url = None
    
    def start_session(self, hostname: str):
        """Initialize a new diagnostic session"""
        short_hostname = hostname.split('.')[0] if '.' in hostname else hostname
        timestamp = datetime.now().strftime('%y%m%d-%H%M')
        self.session_title = f"HBAI-{short_hostname}-{timestamp}"
        
        # Try to create chat session
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        payload = {"chat": {"title": self.session_title, "model": self.model}}
        
        try:
            response = requests.post(
                self.chat_new_endpoint,
                headers=headers,
                json=payload,
                timeout=30,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                self.chat_id = data.get('id')
                if self.chat_id:
                    self.chat_url = f"{self.api_url}/c/{self.chat_id}"
                    self.audit.log('INFO', f'Created chat: {self.session_title}')
        except:
            pass
        
        # Initialize system message with strict formatting rules
        system_msg = """You are an expert Linux systems administrator conducting disk space diagnosis.

CRITICAL RULES:
1. Always respond in EXACT format shown
2. Use NEXT_COMMAND: and EXPLANATION: tags
3. Commands must be READ-ONLY
4. Never repeat commands already executed

Session: """ + self.session_title + """
System: """ + hostname
        
        self.messages = [{"role": "system", "content": system_msg}]
    
    def get_next_diagnostic_command(self, problem_context: Dict, conversation_history: List[Dict]) -> Dict:
        """Get next diagnostic command from AI"""
        
        user_message = self._build_context_message(problem_context, conversation_history)
        
        self.messages.append({"role": "user", "content": user_message})
        self._persist_message_to_chat("user", user_message)
        
        response = self._send_to_ai()
        
        if not response:
            return {'success': False, 'error': 'No response from AI'}
        
        self.messages.append({"role": "assistant", "content": response})
        self._persist_message_to_chat("assistant", response)
        
        result = self._parse_interactive_response(response)
        result['session_title'] = self.session_title
        result['chat_url'] = self.chat_url
        
        return result
    
    def _build_context_message(self, context: Dict, history: List[Dict]) -> str:
        """Build user message with current problem context and execution history"""
        
        if not history:
            # First message
            msg = "DISK SPACE ISSUE:\n"
            msg += f"- System: {context['hostname']}\n"
            msg += f"- Mount Point: {context['mount_point']}\n"
            msg += f"- Usage: {context['usage_percent']}%\n"
            msg += f"- Used: {context['used_gb']}GB of {context['total_gb']}GB\n"
            msg += f"- Free: {context['free_gb']}GB\n\n"
            msg += "CRITICAL: You must respond EXACTLY in this format (no other text):\n\n"
            msg += "NEXT_COMMAND: [the exact command to run]\n"
            msg += "EXPLANATION: [one sentence why this helps]\n\n"
            msg += "IMPORTANT: For find commands, ALWAYS use '+' NOT '\\;'\n"
            msg += "WRONG: find /path -exec ls {} \\;\n"
            msg += "RIGHT:  find /path -exec ls {} +\n\n"
            msg += "Example response:\n"
            msg += f"NEXT_COMMAND: du -sh {context['mount_point']}/* | sort -rh | head -20\n"
            msg += "EXPLANATION: This will show the 20 largest directories to identify what is using space."
            return msg
        
        # Build message showing ALL command history
        msg = "COMMANDS ALREADY EXECUTED (DO NOT REPEAT):\n\n"
        
        for i, cmd in enumerate(history, 1):
            if cmd.get('executed'):
                msg += f"{i}. {cmd['command']}"
                if cmd['success']:
                    msg += " - SUCCESS\n"
                    output = cmd['stdout'][:500] if cmd['stdout'] else 'No output'
                    msg += f"   Output: {output}\n"
                else:
                    msg += " - FAILED\n"
                msg += "\n"
            else:
                msg += f"{i}. {cmd['command']} - REJECTED BY USER\n\n"
        
        # Show latest result in detail
        latest = history[-1]
        msg += "\nLATEST RESULT:\n"
        if latest.get('executed') and latest['success']:
            msg += f"Command: {latest['command']}\n"
            msg += f"Output:\n{latest['stdout'][:2000]}\n"
            if len(latest['stdout']) > 2000:
                msg += "(output truncated)\n"
        
        msg += "\nCRITICAL: Respond EXACTLY in this format:\n\n"
        msg += "NEXT_COMMAND: [exact NEW command - must be DIFFERENT from all commands above]\n"
        msg += "EXPLANATION: [why this helps]\n\n"
        msg += "OR if you have enough information to make recommendations:\n\n"
        msg += "DIAGNOSIS_COMPLETE: true\n"
        msg += "FINAL_ANALYSIS: [your complete analysis]\n"
        msg += "RECOMMENDED_ACTIONS:\n"
        msg += "1. [action with estimated space freed]\n"
        msg += "2. [action with estimated space freed]"
        
        return msg
    
    def _send_to_ai(self) -> Optional[str]:
        """Send full conversation to AI and get response"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        payload = {
            "model": self.model,
            "messages": self.messages,
            "stream": False
        }
        
        if self.chat_id:
            payload["chat_id"] = self.chat_id
        
        try:
            response = requests.post(
                self.chat_endpoint,
                headers=headers,
                json=payload,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.audit.log('ERROR', f'AI API returned status {response.status_code}')
                return None
            
            data = response.json()
            choices = data.get('choices', [])
            if not choices:
                return None
            
            return choices[0].get('message', {}).get('content', '')
            
        except requests.exceptions.Timeout:
            self.audit.log('ERROR', f'AI API timeout after {self.timeout}s')
            return None
        except Exception as e:
            self.audit.log('ERROR', f'AI API error: {str(e)}')
            return None
    

    def _persist_message_to_chat(self, role: str, content: str):
        """Persist messages by updating the full chat object"""
        if not self.chat_id:
            return
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        try:
            # Fetch current chat
            get_response = requests.get(
                f"{self.api_url}/api/v1/chats/{self.chat_id}",
                headers=headers,
                timeout=10,
                verify=self.verify_ssl
            )
            
            if get_response.status_code != 200:
                self.audit.log('WARNING', f'Failed to fetch chat: {get_response.status_code}')
                return
            
            chat_data = get_response.json()
            
            # Get existing messages or initialize
            messages = chat_data.get('chat', {}).get('messages', [])
            
            # Add our new message with proper structure
            messages.append({
                "id": str(uuid.uuid4()),
                "role": role,
                "content": content,
                "timestamp": int(time.time())
            })
            
            # Update chat object
            chat_data['chat']['messages'] = messages
            
            # Post back
            update_response = requests.post(
                f"{self.api_url}/api/v1/chats/{self.chat_id}",
                headers=headers,
                json=chat_data,
                timeout=10,
                verify=self.verify_ssl
            )
            
            if update_response.status_code == 200:
                self.audit.log('DEBUG', f'Persisted {role} message to chat')
            else:
                self.audit.log('WARNING', f'Failed to update chat: {update_response.status_code}')
                
        except Exception as e:
            self.audit.log('WARNING', f'Error persisting message: {str(e)}')

    def _parse_interactive_response(self, response: str) -> Dict:
        """Parse AI response for next command or final analysis"""
        
        # DEBUG: Show what AI actually said
        print("\n" + "="*80)
        print("DEBUG: AI Raw Response:")
        print(response)
        print("="*80 + "\n")
        
        if 'DIAGNOSIS_COMPLETE' in response and 'true' in response:
            analysis_match = re.search(r'FINAL_ANALYSIS:\s*(.+?)(?=RECOMMENDED_ACTIONS:|$)', 
                                     response, re.DOTALL | re.IGNORECASE)
            final_analysis = analysis_match.group(1).strip() if analysis_match else ''
            
            actions = []
            actions_section = re.search(r'RECOMMENDED_ACTIONS:(.*?)$', 
                                      response, re.DOTALL | re.IGNORECASE)
            if actions_section:
                actions_text = actions_section.group(1)
                action_lines = re.findall(r'^\d+\.\s*(.+)$', actions_text, re.MULTILINE)
                actions = action_lines
            
            return {
                'success': True,
                'done': True,
                'final_analysis': final_analysis,
                'recommended_actions': actions
            }
        
        command_match = re.search(r'NEXT_COMMAND:\s*(.+?)(?:\n|$)', response)
        explanation_match = re.search(r'EXPLANATION:\s*(.+?)(?:\n|$)', response)
        
        if command_match:
            return {
                'success': True,
                'done': False,
                'command': command_match.group(1).strip(),
                'explanation': explanation_match.group(1).strip() if explanation_match else ''
            }
        
        self.audit.log('WARNING', 'Could not parse AI response')
        return {
            'success': False,
            'error': 'Could not parse AI response'
        }
