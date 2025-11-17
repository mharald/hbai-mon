#!/usr/bin/env python3
"""
Interactive AI Analyzer Module for HBAI-MON v3
Provides conversational AI diagnosis using Ollama
"""

import requests
import json
import time
import re
from typing import Dict, List, Optional
import urllib3
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class InteractiveAIAnalyzer:
    """Interactive AI analyzer that conducts conversational diagnosis"""
    
    def __init__(self, api_config: dict, audit_logger):
        self.api_url = api_config.get('url', 'https://ai.internal.boehmecke.org')
        self.model = api_config.get('model', 'qwen2.5:3b')
        self.api_key = api_config.get('key', '')
        self.timeout = int(api_config.get('timeout', 300))  # 5 minute default
        self.verify_ssl = api_config.get('verify_ssl', 'false').lower() == 'true'
        self.audit = audit_logger
        
        # API endpoints
        self.chat_endpoint = f"{self.api_url}/api/chat/completions"
    
    def get_next_diagnostic_command(self, problem_context: Dict, 
                                   conversation_history: List[Dict]) -> Dict:
        """
        Get the next diagnostic command from AI based on conversation history
        
        Returns dict with:
        - success: bool
        - command: str (the command to execute)
        - explanation: str (why this command)
        - done: bool (whether diagnosis is complete)
        - final_analysis: str (if done=True)
        - recommended_actions: list (if done=True)
        """
        
        # Build the conversation prompt
        prompt = self._build_interactive_prompt(problem_context, conversation_history)
        
        # Send to AI
        response = self._send_to_ai(prompt)
        
        if not response:
            return {
                'success': False,
                'error': 'No response from AI'
            }
        
        # Parse the response
        return self._parse_interactive_response(response)
    
    def _build_interactive_prompt(self, context: Dict, history: List[Dict]) -> str:
        """Build prompt for next diagnostic step"""
        
        prompt = f"""You are an expert Linux systems administrator conducting an interactive diagnosis.

CURRENT ISSUE:
- System: {context['hostname']}
- Mount Point: {context['mount_point']}
- Disk Usage: {context['usage_percent']}%
- Used: {context['used_gb']}GB of {context['total_gb']}GB
- Free: {context['free_gb']}GB

Your goal is to diagnose the root cause through targeted, READ-ONLY commands.

IMPORTANT RULES:
1. Propose ONE diagnostic command at a time
2. Commands must be READ-ONLY (no rm, delete, truncate, etc.)
3. Start with broad analysis, then drill down based on results
4. Check if databases/files are actually in use before recommending deletion
5. For databases with old names (like "observium2023"), verify they're not still active

"""
        
        # Add conversation history
        if history:
            prompt += "DIAGNOSIS HISTORY:\n"
            for i, item in enumerate(history, 1):
                if item.get('executed'):
                    prompt += f"\nStep {i}: {item['command']}\n"
                    if item['success']:
                        # Include only first 2000 chars of output to avoid token limits
                        output = item['stdout'][:2000] if item['stdout'] else 'No output'
                        prompt += f"Output:\n{output}\n"
                        if len(item['stdout']) > 2000:
                            prompt += "... (output truncated)\n"
                    else:
                        prompt += f"Failed: {item.get('stderr', 'Unknown error')}\n"
                else:
                    prompt += f"\nStep {i}: {item['command']} (rejected by user)\n"
        
        prompt += """

Based on the above, provide your next step.

If you need more information to diagnose:
Respond with:
NEXT_COMMAND: [exact command to run]
EXPLANATION: [why this command helps diagnose the issue]

If you have enough information to make recommendations:
Respond with:
DIAGNOSIS_COMPLETE: true
FINAL_ANALYSIS: [your complete analysis of the root cause]
RECOMMENDED_ACTIONS:
1. [First action with estimated space freed]
2. [Second action with estimated space freed]
...

For databases with old-looking names, always verify with commands like:
- mysql -e "SELECT NOW() as current_time, MAX(UPDATE_TIME) as last_update FROM information_schema.TABLES WHERE TABLE_SCHEMA='database_name';"
- lsof | grep database_name (to check if files are open)
- ps aux | grep database_name (to check running processes)

Remember: Be thorough but efficient. Don't recommend deletion without verification."""
        
        return prompt
    
    def _send_to_ai(self, prompt: str) -> Optional[str]:
        """Send prompt to AI and get response"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "stream": False
        }
        
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
    
    def _parse_interactive_response(self, response: str) -> Dict:
        """Parse AI response for next command or final analysis"""
        
        # Check if diagnosis is complete
        if 'DIAGNOSIS_COMPLETE' in response and 'true' in response:
            # Extract final analysis
            analysis_match = re.search(r'FINAL_ANALYSIS:\s*(.+?)(?=RECOMMENDED_ACTIONS:|$)', 
                                     response, re.DOTALL | re.IGNORECASE)
            final_analysis = analysis_match.group(1).strip() if analysis_match else ''
            
            # Extract recommended actions
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
        
        # Extract next command
        command_match = re.search(r'NEXT_COMMAND:\s*(.+?)(?:\n|$)', response)
        explanation_match = re.search(r'EXPLANATION:\s*(.+?)(?:\n|$)', response)
        
        if command_match:
            return {
                'success': True,
                'done': False,
                'command': command_match.group(1).strip(),
                'explanation': explanation_match.group(1).strip() if explanation_match else ''
            }
        
        # Couldn't parse response
        self.audit.log('WARNING', 'Could not parse AI response', {'response': response[:200]})
        return {
            'success': False,
            'error': 'Could not parse AI response'
        }
