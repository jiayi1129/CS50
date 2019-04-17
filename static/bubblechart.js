$( document ).ready(function(){


  var button = document.getElementById("createscatterplot");

    button.onclick = function(){

        var scatterplot = document.getElementById("scatterplot");
        var input = document.getElementById("data").value.split(",");
        var xmin = document.getElementById("xmin").value;
        var xmax = document.getElementById("xmax").value;
        var ymin = document.getElementById("ymin").value;
        var ymax = document.getElementById("ymax").value;
        var xstep = document.getElementById("xstep").value;
        var ystep = document.getElementById("ystep").value;
        var bordercolour = document.getElementById("colour2").value.split(",");
        var borderwidth = document.getElementById("borderwidth").value.split(",");
        var colour = document.getElementById("colour").value.split(",");
        var title = document.getElementById("title").value;
        var xlabel = document.getElementById("xlabel").value;
        var ylabel = document.getElementById("ylabel").value;
        var label = document.getElementById("bubblelabel").value.split(",");

        var x = 0;
        var y = 1;
        var z = 2;
        var i;
        var datasets = [];
        for (i=0; i < input.length/3; i++)
        {
            var xco = input[x];
            var yco = input[y];
            var zco = input[z];
            datasets.push({label: label[i], data:[{x:xco,y:yco,r:zco,}], backgroundColor: colour[i], borderColor: bordercolour[i], borderWidth: parseFloat(borderwidth[i])},);

            x += 3;
            y += 3;
            z += 3;
        }


        var ctxSc = document.getElementById('scatterplot').getContext('2d');
        var scatterData = {datasets};

        var myscatterplot = new Chart(ctxSc, {
            type: 'bubble',
            data: scatterData,
            options: {
                title: {
                    display: true,
                    text: title
                },
            scales: {
                xAxes: [{
                    ticks: {
                        min: parseFloat(xmin),
                        max: parseFloat(xmax),
                        stepSize: parseFloat(xstep)
                        },
                    scaleLabel: {
                        display: true,
                        labelString: xlabel
                        }
                    }],
                yAxes: [{
                    ticks: {
                        min: parseFloat(ymin),
                        max: parseFloat(ymax),
                        stepSize: parseFloat(ystep)
                        },
                    scaleLabel: {
                        display: true,
                        labelString: ylabel
                        }
                    }],
                },
            }
        });
    // Background Colour
    backgroundcolour = document.getElementById("backgroundcolour").value;
    scatterplot.style.backgroundColor = backgroundcolour;
    };



      //onclick event for add colour button
  document.getElementById("addcolourbutton").onclick = function(){
    colourselector = document.getElementById("colourselector").value;
    colour = document.getElementById("colour").value;
    document.getElementById("colour").value = colour + "#" + colourselector + ",";
  };

  //onclick event for add colour button (2)
  document.getElementById("addcolourbutton2").onclick = function(){
    colourselector2 = document.getElementById("colourselector2").value;
    colour = document.getElementById("colour2").value;
    document.getElementById("colour2").value = colour + "#" + colourselector2 + ",";
  };


    // download function
    $('#spdownload').click(function(){
        html2canvas(document.querySelector('#scatterplot')).then(function(canvas) {

            console.log(canvas);
            saveAs(canvas.toDataURL(), 'mycanvas.png');
        });
    });

    function saveAs(uri, filename) {

    var link = document.createElement('a');

    if (typeof link.download === 'string') {

        link.href = uri;
        link.download = filename;

        //Firefox requires the link to be in the body
        document.body.appendChild(link);

        //simulate click
        link.click();

        //remove the link when done
        document.body.removeChild(link);

    } else {

        window.open(uri);

    }
    }


});