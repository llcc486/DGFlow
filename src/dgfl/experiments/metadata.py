"""User-facing experiment metadata stays separate from opaque run identifiers."""
import unicodedata
from datetime import datetime


def normalize_text(value, *, field):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field} must be a string')
    allowed = '\t\n\r' if field == 'description' else ''
    if any((unicodedata.category(char) == 'Cc' and char not in allowed)
           or (field == 'name' and char in '\u2028\u2029') for char in value):
        raise ValueError(f'{field} contains unsupported control characters')
    value = value.strip()
    if not value:
        return None
    limit = 80 if field == 'name' else 1000
    if len(value) > limit:
        raise ValueError(f'{field} cannot exceed {limit} characters')
    return value


def normalize_metadata(config):
    result = dict(config)
    for field in ('name', 'description'):
        value = normalize_text(result.get(field), field=field)
        if value is None:
            result.pop(field, None)
        else:
            result[field] = value
    return result


def record_metadata(record):
    config = record.get('config') or {}
    result = {}
    for field in ('name', 'description'):
        candidates = (record.get(field), config.get(field))
        result[field] = next((value.strip() for value in candidates
                              if isinstance(value, str) and value.strip()), None)
    return result


def display_name(record):
    name = record_metadata(record)['name']
    if name:
        return name
    created = record.get('created_at')
    dataset = (record.get('config') or {}).get('dataset', 'mnist')
    label = {'mnist':'MNIST', 'cifar10':'CIFAR-10'}.get(dataset, '未命名') + ' 实验'
    if isinstance(created, str) and created:
        try:
            return label + ' · ' + datetime.fromisoformat(created).astimezone().strftime('%m/%d %H:%M')
        except ValueError:
            pass
    return label
