# Upcoming: tag system and searching!!!
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

tags = ['work', 'personal', 'dev', 'entertainment', 'finance', 'email']
tag_completer = WordCompleter(tags, ignore_case=True)

# Prompt with autocomplete
selected_tag = prompt('Enter tag: ', completer=tag_completer)
print(f'Selected: {selected_tag}')
