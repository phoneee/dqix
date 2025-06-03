"""Base CLI class for DQIX.

This module provides a base class for building interactive CLI applications
using Click and Rich for better user experience.
"""

import os
import shlex
from typing import Any, Callable, Dict, List, Optional, Type

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

console = Console()

class InteractiveCLI:
    """Base class for interactive CLI applications."""
    
    def __init__(self, name: str, description: str):
        """Initialize CLI.
        
        Args:
            name: Name of the CLI application
            description: Description of the CLI application
        """
        self.name = name
        self.description = description
        self.commands: Dict[str, Callable] = {}
        self.console = Console()
        
    def add_command(self, name: str, func: Callable) -> None:
        """Add a command to the CLI.
        
        Args:
            name: Command name
            func: Command function
        """
        self.commands[name] = func
        
    def print_help(self) -> None:
        """Print help message."""
        table = Table(title=f"{self.name} - {self.description}")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="green")
        
        for name, func in self.commands.items():
            table.add_row(name, func.__doc__ or "")
            
        self.console.print(table)
        
    def print_error(self, message: str) -> None:
        """Print error message.
        
        Args:
            message: Error message
        """
        self.console.print(f"[bold red]Error:[/bold red] {message}")
        
    def print_success(self, message: str) -> None:
        """Print success message.
        
        Args:
            message: Success message
        """
        self.console.print(f"[bold green]Success:[/bold green] {message}")
        
    def print_info(self, message: str) -> None:
        """Print info message.
        
        Args:
            message: Info message
        """
        self.console.print(f"[bold blue]Info:[/bold blue] {message}")
        
    def print_markdown(self, content: str) -> None:
        """Print markdown content.
        
        Args:
            content: Markdown content
        """
        self.console.print(Markdown(content))
        
    def print_panel(self, content: str, title: Optional[str] = None) -> None:
        """Print content in a panel.
        
        Args:
            content: Panel content
            title: Panel title
        """
        self.console.print(Panel(content, title=title))
        
    def prompt(self, message: str, default: Optional[str] = None) -> str:
        """Prompt user for input.
        
        Args:
            message: Prompt message
            default: Default value
            
        Returns:
            User input
        """
        if default:
            return click.prompt(message, default=default)
        return click.prompt(message)
        
    def confirm(self, message: str, default: bool = True) -> bool:
        """Prompt user for confirmation.
        
        Args:
            message: Confirmation message
            default: Default value
            
        Returns:
            True if confirmed, False otherwise
        """
        return click.confirm(message, default=default)
        
    def run_command(self, command: str) -> None:
        """Run a command.
        
        Args:
            command: Command to run
        """
        try:
            parts = shlex.split(command)
            cmd_name = parts[0]
            args = parts[1:]
            
            if cmd_name in self.commands:
                self.commands[cmd_name](*args)
            else:
                self.print_error(f"Unknown command: {cmd_name}")
        except Exception as e:
            self.print_error(str(e))
            
    def start(self) -> None:
        """Start interactive CLI session."""
        self.print_markdown(f"# {self.name}\n\n{self.description}")
        self.print_help()
        
        while True:
            try:
                command = click.prompt("\nEnter command", type=str)
                
                if command.lower() in ("exit", "quit"):
                    break
                    
                self.run_command(command)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.print_error(str(e))
                
        self.print_info("Goodbye!") 