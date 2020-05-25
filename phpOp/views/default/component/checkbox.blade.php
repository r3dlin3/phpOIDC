<div class="form-group form-check">
    <input type="checkbox" name="{{ $id }}" id="{{ $id }}">
    <label for="{{ $id }}" class="custom-control-label">@_e($name)</label>
    @if ($help)
    <small id="help-{{ $id }}" class="form-text text-muted">
        @_e('help-'. $id)
    </small>
    @endif
    @if ($error_message)
    <div class="invalid-feedback">
        {{ $error_message }}
    </div>
    @endif
</div>