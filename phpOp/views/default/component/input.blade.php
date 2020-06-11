@php
if (isset($rules)) {
    if (array_key_exists('minlength', $rules) || array_key_exists('maxlength', $rules)) {
        $attr .= ' pattern=".{'. $rules['minlength'] .','. $rules['maxlength'] .'}"';
    }
    if (array_key_exists('required', $rules) && $rules['required']) { $attr .= ' required'; }
}
@endphp
<div class="form-group">
    <label for="{{ $name }}">@_e($name)</label>
    <input type="{{ $type }}" class="form-control @if(isset($error_message))is-invalid @endif" id="{{ $name }}" name="{{ $name }}" value="{{ $value }}" {!! $attr !!} @if ($help) aria-describedby="help-{{ $id }}"@endif>
    @if (isset($help))
    <small id="help-{{ $id }}" class="form-text text-muted">
        @_e('help-'. $id)
    </small>
    @endif
    @if (isset($error_message))
    <div class="invalid-feedback">
        @_e($error_message)
    </div>
    @endif
</div>