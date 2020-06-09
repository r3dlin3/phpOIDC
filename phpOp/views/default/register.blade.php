@extends('master')

@section('title')
@_e('TitleRegister')
@endsection

@section('content')
<div class="brand">
    <img src="{!! OP_URL !!}/img/logo.png" alt="logo">
</div>
<div class="card fat">
    <div class="card-body">
        <h4 class="card-title">@_e('Register')</h4>
        @if ($error)
        <div class="alert alert-danger" role="alert">
            Authentication error
        </div>
        @endif

        <form method="POST" class="my-login-validation" action="{!! $action_url !!}" novalidate="">
            @foreach($form as $row)
                @switch($row['type'])
                    @case('text')
                    @case('password')
                    @case('email')
                        @component('component.input',$row)
                        @endcomponent
                        @break
                    @default
                        {{-- Do nothing --}}
                @endswitch
            @endforeach
            <div class="form-group m-0">
                <button type="submit" class="btn btn-primary btn-block" id="register">
                    @_e('Register')
                </button>
            </div>
            <div class="mt-4 text-center">
                @_e('Already have an account?')
                <a href="{!! $login_url !!}">@_e('Login')</a>
            </div>
        </form>
    </div>
</div>
@endsection