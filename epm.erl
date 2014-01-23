#!/usr/bin/env escript

-mode(compile).
-include_lib("kernel/include/file.hrl").

-record(fpm, {
  target,
  output,
  force = false,
  loglevel = error :: error | verbose | debug,
  release,
  epoch,
  license,
  vendor,
  category,
  depends = [],
  url,
  description = "no description",
  maintainer,
  post_install,
  pre_uninstall,
  post_uninstall,
  config_files = [],
  name,
  replaces = [],
  conflicts = [],
  version,
  arch,
  cwd = ".",
  gpg,
  paths = []
}).


main([]) ->
  help(),
  erlang:halt(1);

main(Args) ->
  State = getopt(Args),
  make_package(State),
  ok.


fpm_error(Format) ->
  fpm_error(Format, []).

fpm_error(Format, Args) ->
  io:format(Format ++ "\n", Args),
  halt(1).



%  $$$$$$\             $$\                          $$\     
% $$  __$$\            $$ |                         $$ |    
% $$ /  \__| $$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\ $$$$$$\   
% $$ |$$$$\ $$  __$$\\_$$  _|  $$  __$$\ $$  __$$\\_$$  _|  
% $$ |\_$$ |$$$$$$$$ | $$ |    $$ /  $$ |$$ /  $$ | $$ |    
% $$ |  $$ |$$   ____| $$ |$$\ $$ |  $$ |$$ |  $$ | $$ |$$\ 
% \$$$$$$  |\$$$$$$$\  \$$$$  |\$$$$$$  |$$$$$$$  | \$$$$  |
%  \______/  \_______|  \____/  \______/ $$  ____/   \____/ 
%                                        $$ |               
%                                        $$ |               
%                                        \__|               

getopt(Args) ->
  parse_args(Args, #fpm{}).



parse_args(["-t", "deb"|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{target = deb});

parse_args(["-t", "rpm"|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{target = rpm});

parse_args(["-t", Target|_Args], #fpm{} = _State) ->
  fpm_error("-t '~s' is not supported\n",[Target]);



parse_args(["-s", "dir" | Args], State) ->
  parse_args(Args, State);

parse_args(["-s", Source | _Args], _State) ->
  fpm_error("-s '~s' is not supported", [Source]);


parse_args(["-p", Path|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{output = Path});

parse_args(["--package", Path|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{output = Path});


parse_args(["-f"|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{force = true});

parse_args(["--force"|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{force = true});

parse_args(["-n", V|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{name = V});

parse_args(["--name", V|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{name = V});


parse_args(["--verbose"|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{loglevel = verbose});

parse_args(["--debug"|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{loglevel = debug});


parse_args(["-v", V|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{version = V});

parse_args(["--version", V|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{version = V});

parse_args(["--iteration", I|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{release = I});


parse_args(["--epoch", E|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{epoch = E});


parse_args(["--license", L|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{license = L});

parse_args(["--vendor", L|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{vendor = L});

parse_args(["--category", Desc|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{category = Desc});


parse_args(["--depends", Dep|Args], #fpm{depends = Deps} = State) ->
  parse_args(Args, State#fpm{depends = Deps ++ [Dep]});

parse_args(["-d", Dep|Args], #fpm{depends = Deps} = State) ->
  parse_args(Args, State#fpm{depends = Deps ++ [Dep]});


parse_args(["--conflicts", V|Args], #fpm{conflicts = R} = State) ->
  parse_args(Args, State#fpm{conflicts = R ++ [V]});

parse_args(["--replaces", V|Args], #fpm{replaces = R} = State) ->
  parse_args(Args, State#fpm{replaces = R ++ [V]});


parse_args(["--config-files", V|Args], #fpm{config_files = Conf} = State) ->
  parse_args(Args, State#fpm{config_files = Conf ++ [V]});


parse_args(["-a", V|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{arch = V});

parse_args(["--architecture", V|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{arch = V});


parse_args(["-m", Desc|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{maintainer = Desc});

parse_args(["--maintainer", Desc|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{maintainer = Desc});

parse_args(["--description", Desc|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{description = Desc});


parse_args(["--url", URL|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{url = URL});


parse_args(["--gpg", GPG|Args], #fpm{} = State) ->
  parse_args(Args, State#fpm{gpg = GPG});


parse_args(["--post-install", V|Args], #fpm{} = State) ->
  case file:read_file(V) of
    {ok, Bin} -> parse_args(Args, State#fpm{post_install = Bin});
    {error, E} -> fpm_error("Failed to read post-install ~s", [E])
  end;

parse_args(["--post-uninstall", V|Args], #fpm{} = State) ->
  case file:read_file(V) of
    {ok, Bin} -> parse_args(Args, State#fpm{post_uninstall = Bin});
    {error, E} -> fpm_error("Failed ot read post-uninstall ~s", E)
  end;

parse_args(["--pre-uninstall", V|Args], #fpm{} = State) ->
  case file:read_file(V) of
    {ok, Bin} -> parse_args(Args, State#fpm{pre_uninstall = Bin});
    {error, E} -> fpm_error("Failed to read pre-uninstall ~s", [E])
  end;





parse_args(["--"++Option, _V|Args], #fpm{} = State) ->
  io:format("unknown option '~s'\n", [Option]),
  parse_args(Args, State);

parse_args(["-"++Option, _V|Args], #fpm{} = State) ->
  io:format("unknown option '~s'\n", [Option]),
  parse_args(Args, State);

parse_args(Paths, #fpm{} = State) ->
  State#fpm{paths = Paths}.




validate_package(#fpm{name = undefined}) ->
  fpm_error("name is required");

validate_package(#fpm{arch = undefined}) ->
  fpm_error("arch is required");

validate_package(#fpm{version = undefined}) ->
  fpm_error("version is required");

validate_package(_) ->
  ok.


make_package(#fpm{target = Target} = FPM) ->
  validate_package(FPM),
  case Target of
    deb -> debian(FPM);
    rpm -> rpm(FPM)
  end.



% $$$$$$$\            $$\       $$\                     
% $$  __$$\           $$ |      \__|                    
% $$ |  $$ | $$$$$$\  $$$$$$$\  $$\  $$$$$$\  $$$$$$$\  
% $$ |  $$ |$$  __$$\ $$  __$$\ $$ | \____$$\ $$  __$$\ 
% $$ |  $$ |$$$$$$$$ |$$ |  $$ |$$ | $$$$$$$ |$$ |  $$ |
% $$ |  $$ |$$   ____|$$ |  $$ |$$ |$$  __$$ |$$ |  $$ |
% $$$$$$$  |\$$$$$$$\ $$$$$$$  |$$ |\$$$$$$$ |$$ |  $$ |
% \_______/  \_______|\_______/ \__| \_______|\__|  \__|



debian(#fpm{target = deb, name = Name, version = Version, arch = Arch, output = OutPath, force = Force} = State) ->
  Path = case OutPath of
    undefined -> Name++"_" ++ Version++ "_" ++ Arch ++ ".deb";
    _ -> OutPath
  end,
  case file:read_file_info(Path) of
    {ok, _} when Force ->
      file:delete(Path);
    {ok, _} ->
      fpm_error("Error: file '~s' exists, not overwriting", [Path]);
    {error, enoent} ->
      ok;
    {error, Error} ->
      fpm_error("Error: cannot access output file '~s': ~p", [Path, Error])
  end,

  debian_control(State),
  debian_data(State),
  file:write_file("debian-binary", "2.0\n"),
  os:cmd("ar qc "++Path++" debian-binary control.tar.gz data.tar.gz"),
  file:delete("control.tar.gz"),
  file:delete("data.tar.gz"),
  file:delete("debian-binary"),
  ok.


debian_control(#fpm{post_install = Postinst, pre_uninstall = Prerm, post_uninstall = Postrm} = State) ->
  Files = [{"control", debian_control_content(State)}] ++
    debian_possible_file(conffiles, debian_conf_files(State)) ++
    debian_possible_file(postinst, Postinst) ++
    debian_possible_file(prerm, Prerm) ++
    debian_possible_file(postrm, Postrm),
  file:delete("control.tar.gz"),
  erl_tar:create("control.tar.gz", Files, [compressed]),
  ok.

debian_possible_file(_, undefined) -> [];
debian_possible_file(Name, Content) -> [{atom_to_list(Name),iolist_to_binary(Content)}].

debian_conf_files(#fpm{config_files = Conf}) ->
  [[C,"\n"] || C <- Conf].

debian_control_content(#fpm{name = Name, version = Version, maintainer = Maintainer, conflicts = Conflicts,
  arch = Arch,
  replaces = Replaces, category = Category, url = URL, description = Description}) ->
  Content = [
  debian_header("Package", Name),
  debian_header("Version", Version),
  debian_header("Architecture", Arch),
  debian_header("Maintainer", Maintainer),
  debian_header("Conflicts", join_list(Conflicts)),
  debian_header("Replaces", join_list(Replaces)),
  debian_header("Standards-Version", "3.9.1"),
  debian_header("Section",Category),
  debian_header("Priority", "extra"),
  debian_header("Homepage", URL),
  debian_header("Description", Description)
  ],
  iolist_to_binary(Content).

debian_header(_, undefined) -> "";
debian_header(Key, Value) -> [Key, ": ", Value, "\n"].

join_list([]) -> undefined;
join_list(Items) -> string:join(Items, ", ").



debian_data(#fpm{paths = Paths}) ->
  AllPaths = debian_lookup_files(Paths),
  file:delete("data.tar.gz"),
  % {ok, Tar} = erl_tar:open("data.tar.gz", [write,compressed]),
  % lists:foreach(fun(Path) ->
  %   case filelib:is_dir(Path) of
  %     true ->

  % end, AllPaths), 
  {Dirs, Files} = lists:partition(fun filelib:is_dir/1, AllPaths),
  % io:format("dirs: ~p\n",[Dirs]),
  % io:format("files: ~p\n",[Files]),
  "" = os:cmd(tar()++" --owner=root --numeric-owner --group 0 --no-recursion -cf data.tar "++string:join(Dirs, " ")),
  "" = os:cmd(tar()++" --owner=root --numeric-owner --group 0 -rf data.tar "++string:join(Files, " ")),
  "" = os:cmd("gzip data.tar"),
  % os:cmd(tar()++" --owner=root --group=root  --no-recursion -cf data.tar.gz "++string:join(AllPaths, " ")),
  ok.

debian_lookup_files(Dirs) ->
  debian_lookup_files(Dirs, sets:new()).

debian_lookup_files([], Set) ->
  lists:usort(sets:to_list(Set));

debian_lookup_files([Dir|Dirs], Set) ->
  Set1 = filelib:fold_files(Dir, ".*", true, fun(Path, Acc) ->
    debian_add_recursive_path(Path, Acc)
  end, Set),
  debian_lookup_files(Dirs, Set1).


debian_add_recursive_path("/", Set) ->
  Set;

debian_add_recursive_path(".", Set) ->
  Set;

debian_add_recursive_path(Path, Set) ->
  debian_add_recursive_path(filename:dirname(Path), sets:add_element(Path, Set)).








tar() ->
  case os:type() of
    {unix,darwin} -> "gnutar";
    {unix,linux} -> "tar"
  end.







% $$$$$$$\  $$$$$$$\  $$\      $$\ 
% $$  __$$\ $$  __$$\ $$$\    $$$ |
% $$ |  $$ |$$ |  $$ |$$$$\  $$$$ |
% $$$$$$$  |$$$$$$$  |$$\$$\$$ $$ |
% $$  __$$< $$  ____/ $$ \$$$  $$ |
% $$ |  $$ |$$ |      $$ |\$  /$$ |
% $$ |  $$ |$$ |      $$ | \_/ $$ |
% \__|  \__|\__|      \__|     \__|



rpm(#fpm{paths = Dirs0, output = OutPath, force = Force, name = Name0, version = Version0, arch = Arch0, release = Release0} = FPM) ->
  Arch1 = case Arch0 of
    "amd64" -> "x86_64";
    _ -> Arch0
  end,

  Release1 = case Release0 of
    undefined -> "1";
    _ -> Release0
  end,

  RPMPath = case OutPath of
    undefined -> Name0++"-" ++ Version0++ "-" ++ Release1 ++ "." ++ Arch1 ++ ".rpm";
    _ -> OutPath
  end,
  case file:read_file_info(RPMPath) of
    {ok, _} when Force ->
      file:delete(RPMPath);
    {ok, _} ->
      fpm_error("Error: file '~s' exists, not overwriting", [RPMPath]);
    {error, enoent} ->
      ok;
    {error, Error} ->
      fpm_error("Error: cannot access output file '~s': ~p", [RPMPath, Error])
  end,
  
  Name = iolist_to_binary(Name0),
  Version = iolist_to_binary(Version0),
  Arch = iolist_to_binary(Arch1),
  Release = iolist_to_binary(Release1),

  % It is a problem: how to store directory names. RPM requires storing them in "/etc/"  and "flussonic.conf"
  % cpio required: "etc/flussonic.conf"
  Dirs = lists:map(fun
    ("./" ++ Dir) -> Dir;
    ("/" ++ _ = Dir) -> error({absoulte_dir_not_allowed,Dir});
    (Dir) -> Dir
  end, Dirs0),

  % Need to sort files because mapFind will make bsearch to find them
  Files = rpm_load_file_list(Dirs),
  CPIO = zlib:gzip(cpio(Files)),

  Info1 = [
    {summary, FPM#fpm.description},
    {description, FPM#fpm.description},
    % {buildhost, <<"dev.flussonic.com">>},
    {vendor, FPM#fpm.vendor},
    {license, FPM#fpm.license},
    {packager, FPM#fpm.maintainer},
    {group, FPM#fpm.category},
    {url, FPM#fpm.url}
  ],

  Info2 = [{K,iolist_to_binary(V)} || {K,V} <- Info1, V =/= undefined],

  HeaderAddedTags = Info2 ++ [{name,Name},{version,Version},{release,Release},{arch,Arch},{size,iolist_size(CPIO)}],

  Header = rpm_header(HeaderAddedTags, Files),
  MD5 = crypto:hash(md5, [Header, CPIO]),


  GPGSign = case FPM#fpm.gpg of
    undefined -> 
      [];
    GPG ->
      file:write_file("signed-data", [Header, CPIO]),
      os:cmd("gpg --batch --no-armor --no-secmem-warning -u "++GPG++" -sbo out.sig signed-data"),
      {ok, PGP} = file:read_file("out.sig"),
      file:delete("signed-data"),
      file:delete("out.sig"),

      file:write_file("signed-data", [Header]),
      os:cmd("gpg --batch --no-armor --no-secmem-warning -u "++GPG++" -sbo out.sig signed-data"),
      {ok, RSA} = file:read_file("out.sig"),
      file:delete("signed-data"),
      file:delete("out.sig"),

      [{pgp_header,{bin,PGP}},{rsa_header,{bin,RSA}}]
  end,


  Signature = [{sha1_header,hex(crypto:hash(sha, [Header]))}] ++ GPGSign++
    [{signature_size,iolist_size(Header) + iolist_size(CPIO)},
    {md5_header,{bin,MD5}}],


  {ok, F} = file:open(RPMPath, [binary, write, raw]),
  ok = file:write(F, rpm_lead(Name)),
  ok = file:write(F, rpm_signatures(Signature)),
  ok = file:write(F, Header),
  % {ok, CpioPos} = file:position(F, cur),
  % io:format("Write cpio at offset ~B\n", [CpioPos]),
  ok = file:write(F, CPIO),
  % dump_cpio0(iolist_to_binary(zlib:gunzip(CPIO))),
  ok.

hex(Bin) ->
  iolist_to_binary(string:to_lower(lists:flatten([io_lib:format("~2.16.0B", [I]) || <<I>> <= Bin]))).

rpm_lead(Name) ->
  Magic = <<16#ed, 16#ab, 16#ee, 16#db>>,
  Major = 3,
  Minor = 0,
  Type = 0,
  Arch = 1,

  OS = 1, % Linux
  SigType = 5, % new "Header-style" signatures
  Name0 = iolist_to_binary([Name, binary:copy(<<0>>, 66 - size(Name))]),

  Reserve = binary:copy(<<0>>, 16),
  Lead = <<Magic:4/binary, Major, Minor, Type:16, Arch:16, Name0:66/binary, OS:16, SigType:16, Reserve:16/binary>>,
  96 = size(Lead),
  Lead.



rpm_signatures(Headers) ->
  {_Magic,Index0, Data0} = rpm_pack_header(Headers),

  HeaderSign = <<0,0,0,62, 0,0,0,7, (-(iolist_size(Index0)+16)):32/signed, 0,0,0,16>>,
  {Magic,Index, Data} = rpm_magic(length(Headers)+1, [rpm_pack_index({header_signatures,bin,iolist_size(Data0),size(HeaderSign)})|Index0], [Data0,HeaderSign]),

  Pad = rpm_pad8(Data),
  % io:format("Write signature index_size:~B, header_size:~B, pad:~B\n", [iolist_size(Index), iolist_size(Data), iolist_size(Pad)]),
  [Magic, Index, [Data,Pad]].

rpm_pad8(Data) -> rpm_pad(Data, 8).
% pad4(Data) -> pad(Data, 4).

rpm_pad(Data, N) ->
  Pad = binary:copy(<<0>>, iolist_size(Data) rem N),
  Pad.


rpm_load_file_list(Dirs) ->
  Files1 = lists:usort(lists:flatmap(fun(Dir) -> rpm_list(Dir) end, Dirs)),
  Files2 = Files1 -- [<<"etc">>, <<"etc/init.d">>, <<"opt">>],
  Files2.

rpm_list(Dir) ->
  Files1 = filelib:fold_files(Dir, ".*", true, fun(P,L) -> [list_to_binary(P)|L] end, []),
  Files2 = lists:filter(fun(Path) -> 
    {ok, #file_info{type = T}} = file:read_file_info(Path),
    T == regular
  end, Files1),
  Files3 = lists:flatmap(fun(Path) ->
    rpm_ancestors(Path)
  end, Files2),
  Files3.

rpm_ancestors(Path) ->
  case filename:dirname(Path) of
    <<"/">> -> [];
    <<".">> -> [];
    <<"./">> -> [];
    Root -> [Path|rpm_ancestors(Root)]
  end.


utc({{_Y,_Mon,_D},{_H,_Min,_S}} = DateTime) ->
  calendar:datetime_to_gregorian_seconds(DateTime) - calendar:datetime_to_gregorian_seconds({{1970,1,1}, {0,0,0}}).





cpio_pad4(I) when I rem 4 == 0 -> 0;
cpio_pad4(I) -> 4 - (I rem 4).



to_b(I) when is_integer(I) ->
  iolist_to_binary(string:to_lower(lists:flatten(io_lib:format("~8.16.0B", [I])))).

cpio([]) ->
  cpio_pack("TRAILER!!!", 0, 0, 0);

cpio([Path|Paths]) ->
  Rest = cpio(Paths),
  {ok, #file_info{inode = Inode, size = Size, mode = Mode, type = Type}} = file:read_file_info(Path),
  case Type of
    regular ->
      Pack1 = cpio_pack(<<"/", Path/binary>>, Size, Inode, Mode),
      Pad2 = binary:copy(<<0>>, cpio_pad4(Size)),
      {ok, Bin} = file:read_file(Path),
      Pack1 ++ [Bin, Pad2] ++ Rest;
    directory ->
      Pack1 = cpio_pack(<<"/", Path/binary>>, 0, Inode, Mode),
      Pack1 ++ Rest
  end.



now_s() ->
  {Mega, Sec, _} = os:timestamp(),
  Mega*1000000 + Sec.

cpio_pack(Name, Size, Inode, Mode) ->
  Nlinks = if
    Inode == 0 -> 0;
    Size == 0 -> 2;
    true -> 1
  end,
  Major = case Inode of
    0 -> 0;
    _ -> 263
  end,
  ["070701", to_b(Inode), to_b(Mode), to_b(0), to_b(0), to_b(Nlinks), to_b(now_s()), to_b(Size), to_b(Major), to_b(0), to_b(Major), to_b(0),
  to_b(iolist_size(Name)+1), to_b(0), Name, 0, binary:copy(<<0>>, cpio_pad4(iolist_size(Name) + 1 + 110))].



rpm_header(Addons, Files) ->
  Infos = [begin
    {ok, Info} = file:read_file_info(File),
    Info
  end || File <- Files],

  Dirs0 = lists:usort([filename:dirname(F) || F <- Files]),
  Dirs = lists:zip(Dirs0, lists:seq(0,length(Dirs0)-1)),
  Headers = [
    {headeri18ntable, [<<"C">>]}
    ] ++
      Addons ++ 
    [
    {buildtime, utc(erlang:universaltime())},
    {os, <<"linux">>},
    {filesizes, [Size || #file_info{size = Size} <- Infos]},
    {filemodes, {int16, [Mode || #file_info{mode = Mode} <- Infos]}},
    {filemtimes, [utc(Mtime) || #file_info{mtime = Mtime} <- Infos]},
    {fileflags, [case re:run(F, "etc/") of
      {match, _} -> 17;  % Here we must put proper flags on configuration files
      _ -> 2             % Look for typedef enum rpmfileAttrs_e in rpmfi.h
    end || F <- Files]},
    {fileusername, [<<"root">> || _ <- Files]},
    {filegroupname, [<<"root">> || _ <- Files]},
    {filelinktos, [<<>> || _ <- Files]},
    {filerdevs, [0 || _ <- Files]},

    % {requirename,[<<"/bin/bash">>, <<"rpmlib(CompressedFileNames)">>,
    %                  <<"rpmlib(FileDigests)">>,
    %                  <<"rpmlib(PayloadFilesHavePrefix)">>,
    %                  <<"rpmlib(PayloadIsXz)">>]},
    % {requireversion,[<<>>,<<"3.0.4-1">>,<<"4.6.0-1">>,<<"4.0-1">>,<<"5.2-1">>]},
    {rpmversion, <<"4.8.0">>},
    {fileinodes, [inode(F) || F <- Files]},
    {filelangs, [<<>> || _ <- Files]},

    {dirindexes, [proplists:get_value(filename:dirname(F),Dirs) || F <- Files]},
    {basenames, [filename:basename(File) || File <- Files]},
    {dirnames, [<<"/", Dir/binary, "/">> || {Dir, _} <- Dirs]},

    {payloadformat, <<"cpio">>},
    {payloadcompressor, <<"gzip">>},
    {payloadflags, <<"2">>},
    {platform, <<"x86_64-redhat-linux-gnu">>},
    {filecolors, [0 || _ <- Files]},
    {fileclass, [1 || _ <- Files]},
    {classdict, [<<>>, <<"file">>]},
    {filedependsx, [0 || _ <- Files]},
    {filedependsn, [0 || _ <- Files]},
    {filedigestalgo, [8]}
  ],

  {_,Index0, Data0} = rpm_pack_header(Headers),
  % Data1 = [Data0, align(16, iolist_size(Data0))],
  Data1 = Data0,

  % Here goes very important thing: signing with immutable signature. If you move it one byte left-right, everything
  % will be lost.
  %
  % Immutable is a tag that is located in the end of header payload and it looks like index record. It is very confusing.
  % It has a negative offset and this offset MUST be equal to the size of index _without_ this tag.

  Immutable = <<0,0,0,63, 0,0,0,7, (-(iolist_size(Index0)+16)):32, 0,0,0,16>>,
  {Magic, Index, Data} = rpm_magic(length(Headers)+1, [rpm_pack_index({headerimmutable,bin,iolist_size(Data1),size(Immutable)})|Index0], [Data1,Immutable]),

  % io:format("header. index: ~B entries, ~B bytes, data: ~B bytes\n", [length(Headers)+1, iolist_size(Index), iolist_size(Data)]),
  [Magic, Index, Data].

inode(File) ->
  {ok, #file_info{inode = Inode}} = file:read_file_info(File),
  Inode.






% $$\      $$\           $$\   $$\                     $$\                                 $$\                     
% $$ | $\  $$ |          \__|  $$ |                    $$ |                                $$ |                    
% $$ |$$$\ $$ | $$$$$$\  $$\ $$$$$$\    $$$$$$\        $$$$$$$\   $$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\   $$$$$$\  
% $$ $$ $$\$$ |$$  __$$\ $$ |\_$$  _|  $$  __$$\       $$  __$$\ $$  __$$\  \____$$\ $$  __$$ |$$  __$$\ $$  __$$\ 
% $$$$  _$$$$ |$$ |  \__|$$ |  $$ |    $$$$$$$$ |      $$ |  $$ |$$$$$$$$ | $$$$$$$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|
% $$$  / \$$$ |$$ |      $$ |  $$ |$$\ $$   ____|      $$ |  $$ |$$   ____|$$  __$$ |$$ |  $$ |$$   ____|$$ |      
% $$  /   \$$ |$$ |      $$ |  \$$$$  |\$$$$$$$\       $$ |  $$ |\$$$$$$$\ \$$$$$$$ |\$$$$$$$ |\$$$$$$$\ $$ |      
% \__/     \__|\__|      \__|   \____/  \_______|      \__|  \__| \_______| \_______| \_______| \_______|\__|      



rpm_pack_header(Headers) ->
  {Index, Data} = rpm_pack_header0(Headers, [], [], 0),
  rpm_magic(length(Headers), Index, Data).

rpm_magic(EntryCount, Index, Data) ->
  Bytes = iolist_size(Data),
  Magic = <<16#8e, 16#ad, 16#e8, 16#01, 0:32, EntryCount:32, Bytes:32>>,
  % io:format("pack magic: entries:~B, bytes:~B\n", [EntryCount, Bytes]),
  {Magic,Index, Data}.


rpm_pack_header0([], Index, Data, _) ->
  {lists:reverse([rpm_pack_index(I) || I <- Index]), lists:reverse(Data)};

rpm_pack_header0([{Key,{bin,Value}}|Headers], Index, Data, Offset) when is_binary(Value) ->
  rpm_pack_header0(Headers, [{Key,bin,Offset,size(Value)}|Index], [Value|Data], Offset + size(Value));

rpm_pack_header0([{Key,Value}|Headers], Index, Data, Offset) when is_integer(Value) ->
  Align = rpm_align(4, Offset),
  % Align = <<>>,
  rpm_pack_header0(Headers, [{Key,int32,Offset+size(Align),1}|Index], [<<Value:32>>, Align|Data], Offset + size(Align) + 4);

rpm_pack_header0([{Key,{int16, Values}}|Headers], Index, Data, Offset) ->
  Align = rpm_align(2, Offset),
  % Align = <<>>,
  rpm_pack_header0(Headers, [{Key,int16,Offset+size(Align),length(Values)}|Index], [[<<V:16>> || V <- Values],Align|Data], Offset + size(Align) + 2*length(Values));

rpm_pack_header0([{Key,[Value|_] = Values}|Headers], Index, Data, Offset) when is_integer(Value) ->
  Align = rpm_align(4, Offset),
  % Align = <<>>,
  rpm_pack_header0(Headers, [{Key,int32,Offset+size(Align),length(Values)}|Index], [[<<V:32>> || V <- Values],Align|Data], Offset + size(Align) + 4*length(Values));

rpm_pack_header0([{Key,Value}|Headers], Index, Data, Offset) when is_binary(Value) ->
  String = <<Value/binary, 0>>,
  Pad = <<>>,
  rpm_pack_header0(Headers, [{Key,string,Offset,1}|Index], [Pad,String|Data], Offset + size(String)+size(Pad));

rpm_pack_header0([{Key,[Value|_] = Values}|Headers], Index, Data, Offset) when is_binary(Value) ->
  Size = lists:sum([size(V) + 1 || V <- Values]),
  rpm_pack_header0(Headers, [{Key,string_array,Offset,length(Values)}|Index], [[<<V/binary, 0>> || V <- Values]|Data], Offset + Size).


rpm_align(N, Offset) when Offset rem N == 0 -> <<>>;
rpm_align(N, Offset) -> binary:copy(<<0>>, N - (Offset rem N)).



rpm_pack_index({Tag, Type, Offset, Count}) ->
  <<(rpm_write_tag(Tag)):32, (rpm_write_type(Type)):32, Offset:32, Count:32>>.







% $$$$$$$\             $$\                     $$$$$$$$\                                      
% $$  __$$\            $$ |                    \__$$  __|                                     
% $$ |  $$ | $$$$$$\ $$$$$$\    $$$$$$\           $$ |$$\   $$\  $$$$$$\   $$$$$$\   $$$$$$$\ 
% $$ |  $$ | \____$$\\_$$  _|   \____$$\          $$ |$$ |  $$ |$$  __$$\ $$  __$$\ $$  _____|
% $$ |  $$ | $$$$$$$ | $$ |     $$$$$$$ |         $$ |$$ |  $$ |$$ /  $$ |$$$$$$$$ |\$$$$$$\  
% $$ |  $$ |$$  __$$ | $$ |$$\ $$  __$$ |         $$ |$$ |  $$ |$$ |  $$ |$$   ____| \____$$\ 
% $$$$$$$  |\$$$$$$$ | \$$$$  |\$$$$$$$ |         $$ |\$$$$$$$ |$$$$$$$  |\$$$$$$$\ $$$$$$$  |
% \_______/  \_______|  \____/  \_______|         \__| \____$$ |$$  ____/  \_______|\_______/ 
%                                                     $$\   $$ |$$ |                          
%                                                     \$$$$$$  |$$ |                          
%                                                      \______/ \__|                          




rpm_write_type(T) when is_atom(T) ->
  case lists:keyfind(T, 2, rpm_types()) of
    {I,T} -> I;
    false -> error({unknown_type, T})
  end.


rpm_types() ->
  [{0,null},
  {1,char},
  {2,int8},
  {3,int16},
  {4,int32},
  {5,int64},
  {6,string},
  {7,bin},
  {8,string_array},
  {9,i18n_string}
  ].




% $$$$$$$$\                            
% \__$$  __|                           
%    $$ | $$$$$$\   $$$$$$\   $$$$$$$\ 
%    $$ | \____$$\ $$  __$$\ $$  _____|
%    $$ | $$$$$$$ |$$ /  $$ |\$$$$$$\  
%    $$ |$$  __$$ |$$ |  $$ | \____$$\ 
%    $$ |\$$$$$$$ |\$$$$$$$ |$$$$$$$  |
%    \__| \_______| \____$$ |\_______/ 
%                  $$\   $$ |          
%                  \$$$$$$  |          
%                   \______/           





rpm_write_tag(T) when is_atom(T) ->
  case lists:keyfind(T,2,rpm_tags()) of
    {I,T} -> I;
    false -> 
      case lists:keyfind(T,2,rpm_signature_tags()) of
        {I,T} -> I;
        false -> error({unknown_tag,T})
      end
  end.

rpm_signature_tags() ->
  [
    {1000, signature_size},
    {1002, pgp_header},
    {1004, md5_header},
    {1007, signature_payloadsize}
  ].


rpm_tags() ->
  [
  {62, header_signatures},
  {63, headerimmutable},
  {100, headeri18ntable},
  {268, rsa_header},
  {269, sha1_header},
  {1000, name}, % size for signature
  {1001, version},
  {1002, release}, % pgp for signature
  {1003, epoch},
  {1004, summary}, % md5 for signature
  {1005, description},
  {1006, buildtime},
  {1007, buildhost}, % this is payloadsize for signature
  {1008, installtime},
  {1009, size},
  {1010, distribution},
  {1011, vendor},
  {1012, gif},
  {1013, xpm},
  {1014, license},
  {1015, packager},
  {1016, group},
  {1017, changelog},
  {1018, source},
  {1019, patch},
  {1020, url},
  {1021, os},
  {1022, arch},
  {1023, preinstall},
  {1024, postinstall},
  {1025, preuninstall},
  {1026, postuninstall},
  {1027, old_filenames},
  {1028, filesizes},
  {1029, filestates},
  {1030, filemodes},
  {1031, fileuids},
  {1032, filegids},
  {1033, filerdevs},
  {1034, filemtimes},
  {1035, filedigests},
  {1036, filelinktos},
  {1037, fileflags},
  {1038, root},
  {1039, fileusername},
  {1040, filegroupname},
  {1041, exclude},
  {1042, exlusive},
  {1043, icon},
  {1044, sourcerpm},
  {1045, fileverifyflags},
  {1046, archivesize},
  {1047, providename},
  {1048, requireflags},
  {1049, requirename},
  {1050, requireversion},
  {1051, nosource},
  {1052, nopatch},
  {1053, conflictflags},
  {1054, conflictname},
  {1055, conflictversion},
  {1056, defaultprefix},
  {1057, buildroot},
  {1058, installprefix},
  {1059, excludearch},
  {1060, excludeos},
  {1061, exlusivearch},
  {1062, exlusiveos},
  {1063, autoreqprov},
  {1064, rpmversion},
  {1065, triggerscripts},
  {1066, triggername},
  {1067, triggerversion},
  {1068, triggerflags},
  {1069, triggerindex},
  {1079, verifyscript},
  {1080, changelogtime},
  {1081, changelogname},
  {1082, changelogtext},
  {1085, preinstall_prog},
  {1086, postinstall_prog},
  {1087, preuninstall_prog},
  {1088, postuninstall_prog},
  {1089, buildarch},
  {1090, obsoletename},
  {1092, triggerscript_prog},
  {1093, docdir},
  {1094, cookie},
  {1095, filedevices},
  {1096, fileinodes},
  {1097, filelangs},
  {1098, prefixes},
  {1112, provideflags},
  {1113, provideversion},
  {1114, obsoleteflags},
  {1115, obsoleteversion},
  {1116, dirindexes},
  {1117, basenames},
  {1118, dirnames},
  {1122, optflags},
  {1124, payloadformat},
  {1125, payloadcompressor},
  {1126, payloadflags},
  {1132, platform},
  {1140, filecolors},
  {1141, fileclass},
  {1142, classdict},
  {1143, filedependsx},
  {1144, filedependsn},
  {1145, filedependsdict},
  {5011, filedigestalgo}
  ].






% $$\   $$\           $$\           
% $$ |  $$ |          $$ |          
% $$ |  $$ | $$$$$$\  $$ | $$$$$$\  
% $$$$$$$$ |$$  __$$\ $$ |$$  __$$\ 
% $$  __$$ |$$$$$$$$ |$$ |$$ /  $$ |
% $$ |  $$ |$$   ____|$$ |$$ |  $$ |
% $$ |  $$ |\$$$$$$$\ $$ |$$$$$$$  |
% \__|  \__| \_______|\__|$$  ____/ 
%                         $$ |      
%                         $$ |      
%                         \__|      


help() ->
io:format("
Usage:
    epm [OPTIONS] [ARGS] ...

Parameters:
    [ARGS] ...                    Inputs to the source package type. For the 'dir' type, this is the files and directories you want to include in the package. For others, like 'gem', it specifies the packages to download and use as the gem input

Options:
    --gpg user@host.local         name of GPG key owner to use for signing rpm package
    -t OUTPUT_TYPE                the type of package you want to create (deb, rpm)
    -s INPUT_TYPE                 the package type to use as input (dir only supported)
    -p, --package OUTPUT          The package file path to output.
    -f, --force                   Force output even if it will overwrite an existing file (default: false)
    -n, --name NAME               The name to give to the package
    --verbose                     Enable verbose output
    --debug                       Enable debug output
    -v, --version VERSION         The version to give to the package (default: 1.0)
    --iteration ITERATION         The iteration to give to the package. RPM calls this the 'release'. FreeBSD calls it 'PORTREVISION'. Debian calls this 'debian_revision'
    --epoch EPOCH                 The epoch value for this package. RPM and Debian calls this 'epoch'. FreeBSD calls this 'PORTEPOCH'
    --license LICENSE             (optional) license name for this package
    --vendor VENDOR               (optional) vendor name for this package
    --category CATEGORY           (optional) category this package belongs to
    -d, --depends DEPENDENCY      A dependency. This flag can be specified multiple times. Value is usually in the form of: -d 'name' or -d 'name > version'
    --provides PROVIDES           What this package provides (usually a name). This flag can be specified multiple times.
    --conflicts CONFLICTS         Other packages/versions this package conflicts with. This flag can specified multiple times.
    --replaces REPLACES           Other packages/versions this package replaces. This flag can be specified multiple times.
    --config-files CONFIG_FILES   Mark a file in the package as being a config file. This uses 'conffiles' in debs and %config in rpm. If you have multiple files to mark as configuration files, specify this flag multiple times.
    -a, --architecture ARCHITECTURE The architecture name. Usually matches 'uname -m'. For automatic values, you can use '-a all' or '-a native'. These two strings will be translated into the correct value for your platform and target package type.
    -m, --maintainer MAINTAINER   The maintainer of this package. (default: \"<max@flussonic.com>\")
    --description DESCRIPTION     Add a description for this package. You can include '
                                  ' sequences to indicate newline breaks. (default: \"no description\")
    --url URI                     Add a url for this package. (default: \"http://example.com/no-uri-given\")
    --post-install FILE           a script to be run after package installation
    --pre-install FILE            a script to be run before package installation
    --post-uninstall FILE         a script to be run after package removal
    --pre-uninstall FILE          a script to be run before package removal

").









