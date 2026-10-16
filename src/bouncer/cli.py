"""
Bouncer CLI Interface.
Provides administrative commands for registry validation, human consent issuance,
and audit trail inspection.
"""

from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.bouncer.consent import (
    DEFAULT_SECRET,
    compute_text_sha256,
    issue_consent_token,
)
from src.bouncer.registry import AgentRegistry, RegistryValidationError


app = typer.Typer(
    name="bouncer",
    help="Bouncer: Permission-bounded MCP server and agent registry CLI.",
    add_completion=False,
)
console = Console()


@app.command("validate")
def validate_cmd(
    registry_path: Path = typer.Option(
        Path("registry/agents.yaml"),
        "--path",
        "-p",
        help="Path to agents.yaml manifest.",
    )
):
    """
    Validates agents.yaml for structural integrity, tier bounds, and forbidden tool absence.
    """
    console.print(f"[bold cyan]Validating Agent Registry at:[/] {registry_path}")
    try:
        registry = AgentRegistry.from_yaml_file(registry_path)
    except RegistryValidationError as e:
        console.print(f"[bold red]Validation Failed:[/] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)

    table = Table(title="Bouncer Validated Agent Registry", show_header=True, header_style="bold magenta")
    table.add_column("Agent ID", style="cyan")
    table.add_column("Owner", style="green")
    table.add_column("Tier", style="yellow")
    table.add_column("Human Gate", style="blue")
    table.add_column("Tool Grant", style="white")

    for agent in registry.list_agents():
        table.add_row(
            agent.id,
            agent.owner,
            agent.tier.value,
            agent.human_gate.value,
            ", ".join(agent.tool_grant),
        )

    console.print(table)
    console.print("[bold green][OK] Registry validation passed: No forbidden tools detected.[/]")


@app.command("issue-consent")
def issue_consent_cmd(
    agent_id: str = typer.Option(..., "--agent", "-a", help="Authorized agent ID (e.g. status-reporter)."),
    target_id: str = typer.Option(..., "--target", "-t", help="Target work-system entity (e.g. task-101)."),
    text: Optional[str] = typer.Option(None, "--text", help="Exact text of the comment to carry."),
    approver: str = typer.Option("harsh@example.com", "--approver", help="Human approver email/name."),
    ttl: int = typer.Option(600, "--ttl", help="Token lifetime in seconds (default 600s / 10m)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Bypass interactive confirmation prompt."),
):
    """
    Interactively review and issue a cryptographically signed, single-use consent token.
    Binds sha256(text) to the agent, target, and short TTL.
    """
    if not text:
        text = typer.prompt("Enter exact comment text to authorize")

    text_hash = compute_text_sha256(text)

    review_panel = Panel(
        f"[bold yellow]Agent ID:[/] {agent_id}\n"
        f"[bold yellow]Target Work Entity:[/] {target_id}\n"
        f"[bold yellow]Approver:[/] {approver}\n"
        f"[bold yellow]Token TTL:[/] {ttl}s\n"
        f"[bold yellow]SHA-256 Digest:[/] {text_hash}\n\n"
        f"[bold cyan]Exact Human-Authored Text:[/]\n\"{text}\"",
        title="[bold green]HUMAN REVIEW GATE[/]",
        border_style="green",
    )
    console.print(review_panel)

    if not yes:
        confirmed = typer.confirm("Do you approve carrying this exact human-authored update into the work system?")
        if not confirmed:
            console.print("[bold red]Consent rejected by human reviewer. No token issued.[/]")
            raise typer.Exit(code=1)

    token = issue_consent_token(
        agent_id=agent_id,
        target_id=target_id,
        text=text,
        approver=approver,
        secret=DEFAULT_SECRET,
        ttl_seconds=ttl,
    )

    console.print("\n[bold green][OK] Consent Token Successfully Issued:[/]")
    console.print(f"[bold white on blue] {token} [/]\n")
    console.print("[dim]Pass this token to post_human_authored_comment(target_id, text, consent_token).[/]")


if __name__ == "__main__":
    app()
