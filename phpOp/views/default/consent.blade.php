@extends('master')

@section('title')
@_e('TitleConsent')
@endsection

@section('content')
<div class="brand">
    <img src="{!! OP_URL !!}/img/logo.png" alt="logo">
</div>
<div class="card fat">
    <div class="card-body">
        <h4 class="card-title">@_ef('%s Authorization OP', $site['name'])</h4>
        <div class="media">
            @if (!empty($client['logo_uri']))
            <img src="{!! $client['logo_uri'] !!}" class="mr-3" alt="{{ $client['client_name'] }}">
            @endif
            <div class="media-body">
                <h5 class="mt-0">{{ $client['client_name'] }}</h5>
                @_e('This application wants to access the following information:')
            </div>
        </div>

        <div class="accordion mb-3" id="accordionScopes">
            @foreach ($scopes as $scope)
            <div class="card">
                <div class="card-header py-1 pl-0" id="heading-{{ $scope }}">
                    <h2 class="mb-0">
                        <button class="btn btn-block text-left collapsed py-0" type="button" data-toggle="collapse"
                            data-target="#collapse-{{ $scope }}" aria-expanded="false" aria-controls="collapse-{{ $scope }}">
                            <i class="bi" aria-hidden="true"></i> @_e('label-'.$scope)
                        </button>
                    </h2>
                </div>
                <div id="collapse-{{ $scope }}" class="collapse" aria-labelledby="heading-{{ $scope }}"
                    data-parent="#accordionScopes">
                    <div class="card-body">
                        @_e('desc-' . $scope)
                    </div>
                </div>
            </div>
            @endforeach
        </div>

        <p class="card-text"> 
            @if (!empty($client['policy_uri']) && !empty($client['tos_uri']))
                @_ef('%s has provided a <a href="%s">policy</a> and <a href="%s" class="card-link">terms of use</a>.',$client['client_name'], $client['policy_uri'], $client['tos_uri'])
            @elseif (!empty($client['policy_uri']))
                @_ef('%s has provided a <a href="%s">policy</a>.', $client['client_name'], $client['policy_uri'])
            @elseif (!empty($client['tos_uri']))
                @_ef('%s has provided a <a href="%s" class="card-link">terms of use</a>.', $client['client_name'], $client['tos_uri'])
            @else
            <b>
                @_ef('%s has not provided any policy nor terms of use.', $client['client_name'])
            </b>
            @endif
        </p>
        <form method="POST" class="my-login-validation" action="{!! $action_url !!}" novalidate="">
            <div class="form-check">
                <input class="form-check-input" type="radio" name="trust" id="trustonce" value="once" checked>
                <label class="form-check-label" for="trustonce">
                    @_e('Trust this site this time only')
                </label>
            </div>
            <div class="form-check">
                <input class="form-check-input" type="radio" name="trust" id="trustalways" value="always">
                <label class="form-check-label" for="trustalways">
                    @_e('Trust this site always')
                </label>
            </div>
            <div class="row mt-3">
                <div class="col">
                    <button type="submit" class="btn btn-outline-secondary btn-block" name="confirm" value="denied">
                        @_e('Deny')
                    </button>
                </div>
                <div class="col">
                    <button type="submit" class="btn btn-primary btn-block" tabindex="1" name="confirm" id="confirmed" value="confirmed" autofocus>
                        @_e('Accept')
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>
@endsection